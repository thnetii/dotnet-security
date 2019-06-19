using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace THNETII.Security.WindowsImpersonation
{
    public class WindowsImpersonationTaskScheduler : TaskScheduler, IDisposable
    {
        private readonly BlockingCollection<Task> taskQueue = new BlockingCollection<Task>();
        private readonly HashSet<Thread> runningThreads = new HashSet<Thread>();
        private readonly HashSet<Thread> dedicatedThreads = new HashSet<Thread>();
        private volatile int idleCount = 0;

        public WindowsImpersonationTaskScheduler(int maximumConcurrencyLevel = -1)
            : base()
        {
            if (maximumConcurrencyLevel < 0)
                maximumConcurrencyLevel = Environment.ProcessorCount * 2;

            MaximumConcurrencyLevel = maximumConcurrencyLevel;
        }

        public override int MaximumConcurrencyLevel { get; }

        public TimeSpan ExecutorIdleTimeout { get; set; } = TimeSpan.FromSeconds(15);

        protected override IEnumerable<Task> GetScheduledTasks()
            => taskQueue.ToArray();

        protected override void QueueTask(Task task)
        {
            if (task is null)
                return;

            if (task.CreationOptions.HasFlag(TaskCreationOptions.LongRunning) || taskQueue.IsAddingCompleted)
            {
                var th = new Thread(LongRunningExecutorThreadStart);
                th.Start(task);

                return;
            }

            bool needNewExecutor = runningThreads.Count < MaximumConcurrencyLevel && idleCount < 1;
            taskQueue.Add(task);

            if (needNewExecutor)
            {
                var th = new Thread(NormalTaskExecutorThreadStart);
                th.Start();
            }
        }

        protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued)
        {
            bool isSchedulerThread = IsRunningThread() || IsDedicatedThread();
            if (!isSchedulerThread)
                return false;

            return TryExecuteTask(task);
        }

        private void NormalTaskExecutorThreadStart()
        {
            bool hashSetOp;
            lock (runningThreads)
            { hashSetOp = runningThreads.Add(Thread.CurrentThread); }
            try
            {
                Interlocked.Increment(ref idleCount);
                while (!taskQueue.IsAddingCompleted && taskQueue.TryTake(out Task task, ExecutorIdleTimeout))
                {
                    Interlocked.Decrement(ref idleCount);

                    bool taskExecOp = TryExecuteTask(task);

                    Interlocked.Increment(ref idleCount);
                }
            }
            finally
            {
                lock (runningThreads)
                { hashSetOp = runningThreads.Remove(Thread.CurrentThread); }
            }
        }

        private void LongRunningExecutorThreadStart(object obj)
        {
            if (!(obj is Task task))
            {
                return;
            }

            bool hashSetOp;
            lock (dedicatedThreads)
            { hashSetOp = dedicatedThreads.Add(Thread.CurrentThread); }
            try
            {
                bool taskExecOp = TryExecuteTask(task);
            }
            finally
            {
                lock (dedicatedThreads)
                { hashSetOp = dedicatedThreads.Remove(Thread.CurrentThread); }
            }
        }

        private bool IsRunningThread()
        {
            lock (runningThreads)
            { return runningThreads.Contains(Thread.CurrentThread); }
        }

        private bool IsDedicatedThread()
        {
            lock (dedicatedThreads)
            { return dedicatedThreads.Contains(Thread.CurrentThread); }
        }

        private Thread GetNextRunningThread()
        {
            lock (runningThreads)
            {
                return runningThreads.FirstOrDefault();
            }
        }

        #region IDisposable
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                taskQueue.CompleteAdding();

                while (runningThreads.Count > 0)
                {
                    for (var t = GetNextRunningThread(); t is Thread; t = GetNextRunningThread())
                    {
                        t.Join();
                    }
                }
            }

            taskQueue.Dispose();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~WindowsImpersonationTaskScheduler()
        {
            Dispose(false);
        }
        #endregion
    }
}
