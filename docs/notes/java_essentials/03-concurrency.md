# 03 - 并发编程

多线程、同步、锁、线程池、Android Handler。


## 概念速览

**为什么需要并发？**
- 利用多核 CPU
- 避免 UI 阻塞
- 提高响应性

**Java 并发层次：**

```
High-level:  ExecutorService, CompletableFuture
        ↓
Mid-level:   synchronized, Lock, Atomic*
        ↓
Low-level:   Thread, volatile
```

**Android 特殊性：**
- UI 线程（主线程）不能阻塞
- 后台任务使用 Handler、AsyncTask、Coroutine
- 严格的线程策略（StrictMode）


## 线程基础

### 创建线程

```java
// 方式 1: 继承 Thread
class MyThread extends Thread {
    @Override
    public void run() {
        System.out.println("Thread running: " + getName());
    }
}

new MyThread().start();

// 方式 2: 实现 Runnable (推荐)
Runnable task = () -> System.out.println("Task running");
new Thread(task).start();

// 方式 3: Callable (有返回值)
Callable<Integer> callable = () -> {
    Thread.sleep(1000);
    return 42;
};
```

### 线程状态

```
NEW → RUNNABLE ←→ BLOCKED
         ↓          ↑
    WAITING → TIMED_WAITING
         ↓
    TERMINATED
```

```java
Thread t = new Thread(() -> { });
System.out.println(t.getState());  // NEW
t.start();
System.out.println(t.getState());  // RUNNABLE
```

### 线程控制

```java
// 休眠
Thread.sleep(1000);  // 毫秒

// 等待其他线程
Thread t = new Thread(() -> { ... });
t.start();
t.join();  // 等待 t 结束
t.join(1000);  // 最多等 1 秒

// 中断
t.interrupt();
if (Thread.interrupted()) { ... }
```


## 同步机制

### synchronized

```java
public class Counter {
    private int count = 0;
    
    // 同步方法
    public synchronized void increment() {
        count++;
    }
    
    // 同步块
    public void incrementBlock() {
        synchronized (this) {
            count++;
        }
    }
    
    // 静态同步 (锁类对象)
    public static synchronized void staticMethod() { }
}
```

**锁的选择：**
```java
private final Object lock = new Object();

public void method() {
    synchronized (lock) {  // 推荐：私有锁对象
        // ...
    }
}
```

### volatile

保证可见性，禁止重排序，但**不保证原子性**：

```java
private volatile boolean running = true;

public void stop() {
    running = false;  // 其他线程立即可见
}

public void run() {
    while (running) {
        // ...
    }
}
```

> [!WARNING]
> `volatile` 不适合 `count++` 等复合操作。

### Atomic*

```java
import java.util.concurrent.atomic.*;

AtomicInteger counter = new AtomicInteger(0);
counter.incrementAndGet();  // 原子自增
counter.compareAndSet(0, 1);  // CAS

AtomicReference<String> ref = new AtomicReference<>("init");
ref.set("new");
```


## Lock 接口

### ReentrantLock

```java
import java.util.concurrent.locks.*;

private final Lock lock = new ReentrantLock();

public void method() {
    lock.lock();
    try {
        // 临界区
    } finally {
        lock.unlock();  // 必须在 finally 中释放
    }
}

// tryLock
if (lock.tryLock()) {
    try {
        // 获取到锁
    } finally {
        lock.unlock();
    }
} else {
    // 未获取到
}

// 超时
if (lock.tryLock(1, TimeUnit.SECONDS)) { ... }
```

### ReadWriteLock

读多写少的场景：

```java
private final ReadWriteLock rwLock = new ReentrantReadWriteLock();
private final Lock readLock = rwLock.readLock();
private final Lock writeLock = rwLock.writeLock();

public String read() {
    readLock.lock();
    try {
        return data;
    } finally {
        readLock.unlock();
    }
}

public void write(String newData) {
    writeLock.lock();
    try {
        data = newData;
    } finally {
        writeLock.unlock();
    }
}
```

### Condition

```java
private final Lock lock = new ReentrantLock();
private final Condition notEmpty = lock.newCondition();
private final Condition notFull = lock.newCondition();

public void put(Object item) throws InterruptedException {
    lock.lock();
    try {
        while (isFull()) {
            notFull.await();
        }
        // 添加元素
        notEmpty.signal();
    } finally {
        lock.unlock();
    }
}
```


## 线程池

### ExecutorService

```java
// 固定大小线程池
ExecutorService fixed = Executors.newFixedThreadPool(4);

// 单线程池
ExecutorService single = Executors.newSingleThreadExecutor();

// 缓存线程池 (按需创建)
ExecutorService cached = Executors.newCachedThreadPool();

// 提交任务
fixed.submit(() -> System.out.println("Task"));

// 有返回值
Future<Integer> future = fixed.submit(() -> 42);
int result = future.get();  // 阻塞等待

// 关闭
fixed.shutdown();
fixed.awaitTermination(10, TimeUnit.SECONDS);
```

### ThreadPoolExecutor

```java
ThreadPoolExecutor executor = new ThreadPoolExecutor(
    4,                      // corePoolSize
    8,                      // maximumPoolSize
    60, TimeUnit.SECONDS,   // keepAliveTime
    new LinkedBlockingQueue<>(100),  // 工作队列
    new ThreadPoolExecutor.CallerRunsPolicy()  // 拒绝策略
);
```

**拒绝策略：**

| 策略 | 行为 |
|------|------|
| AbortPolicy | 抛出异常 (默认) |
| CallerRunsPolicy | 调用者线程执行 |
| DiscardPolicy | 静默丢弃 |
| DiscardOldestPolicy | 丢弃最老任务 |


## Android Handler

### 基本用法

```java
// 在主线程创建
Handler handler = new Handler(Looper.getMainLooper());

// 从后台线程发送
new Thread(() -> {
    // 耗时操作
    String result = doBackground();
    
    // 切回主线程更新 UI
    handler.post(() -> {
        textView.setText(result);
    });
}).start();

// 延迟执行
handler.postDelayed(() -> {
    // 延迟 1 秒执行
}, 1000);
```

### Message 和 Runnable

```java
Handler handler = new Handler(Looper.getMainLooper()) {
    @Override
    public void handleMessage(Message msg) {
        switch (msg.what) {
            case 1:
                // 处理消息
                break;
        }
    }
};

// 发送消息
Message msg = Message.obtain();
msg.what = 1;
msg.obj = "data";
handler.sendMessage(msg);
```

### HandlerThread

```java
HandlerThread thread = new HandlerThread("MyThread");
thread.start();

Handler bgHandler = new Handler(thread.getLooper());
bgHandler.post(() -> {
    // 在后台线程执行
});

// 结束时
thread.quitSafely();
```


## 实战场景

### Lab 1: 生产者消费者

```java
public class ProducerConsumer {
    private final Queue<Integer> queue = new LinkedList<>();
    private final int capacity = 10;
    
    public synchronized void produce(int item) throws InterruptedException {
        while (queue.size() == capacity) {
            wait();
        }
        queue.offer(item);
        notifyAll();
    }
    
    public synchronized int consume() throws InterruptedException {
        while (queue.isEmpty()) {
            wait();
        }
        int item = queue.poll();
        notifyAll();
        return item;
    }
}
```

### Lab 2: 并发集合

```java
// 线程安全的 Map
Map<String, Integer> concurrentMap = new ConcurrentHashMap<>();
concurrentMap.put("key", 1);
concurrentMap.computeIfAbsent("key2", k -> 2);

// 线程安全的 List
List<String> copyOnWriteList = new CopyOnWriteArrayList<>();

// 阻塞队列
BlockingQueue<String> blockingQueue = new LinkedBlockingQueue<>();
blockingQueue.put("item");  // 阻塞直到有空间
String item = blockingQueue.take();  // 阻塞直到有元素
```

### Lab 3: CompletableFuture

```java
CompletableFuture<String> future = CompletableFuture
    .supplyAsync(() -> {
        // 异步任务 1
        return "Hello";
    })
    .thenApplyAsync(s -> {
        // 异步任务 2
        return s + " World";
    })
    .thenAccept(System.out::println);

// 组合多个 Future
CompletableFuture<String> f1 = CompletableFuture.supplyAsync(() -> "A");
CompletableFuture<String> f2 = CompletableFuture.supplyAsync(() -> "B");

CompletableFuture.allOf(f1, f2).thenRun(() -> {
    // 两个都完成
});
```


## 常见陷阱

### ❌ 陷阱 1: 死锁

```java
// 线程 1: lock(A) → lock(B)
// 线程 2: lock(B) → lock(A)
// 死锁！

// 解决：统一锁顺序
```

### ❌ 陷阱 2: 忘记释放锁

```java
// 错误
lock.lock();
doSomething();  // 如果抛异常，锁不会释放
lock.unlock();

// 正确
lock.lock();
try {
    doSomething();
} finally {
    lock.unlock();
}
```

### ❌ 陷阱 3: 在 UI 线程做耗时操作

```java
// 错误：直接在主线程
String data = networkRequest();  // ANR!

// 正确：后台执行
new Thread(() -> {
    String data = networkRequest();
    runOnUiThread(() -> updateUI(data));
}).start();
```

### ❌ 陷阱 4: Handler 内存泄漏

```java
// 错误：非静态内部类持有 Activity 引用
class MyHandler extends Handler { ... }

// 正确：静态内部类 + 弱引用
static class MyHandler extends Handler {
    WeakReference<Activity> activityRef;
    // ...
}
```


## 深入阅读

**推荐资源：**
- [Java Concurrency in Practice](https://jcip.net/)
- [Android Handler Mechanism](https://developer.android.com/reference/android/os/Handler)

**相关章节：**
- [02 - 集合框架](./02-collections.md) - 并发集合
- [06 - AOSP 实战](./06-android-java.md) - system_server 线程模型


## 下一步

[04 - JVM 与 ART](./04-jvm-art.md) - 深入运行时
