# 04 - 并发

Rust 的无畏并发：编译时防止数据竞争。


## 概念速览

**Rust 并发的特点：**
- 编译时防止数据竞争
- Send/Sync trait 保证线程安全
- 零成本抽象

**与其他语言对比：**

| 语言 | 数据竞争防护 | 死锁防护 |
|------|-------------|----------|
| C/C++ | 无 | 无 |
| Java | 运行时检测 | 无 |
| Go | 运行时检测 | 无 |
| Rust | 编译时防止 | 无 |


## 线程基础

### 创建线程

```rust
use std::thread;
use std::time::Duration;

fn main() {
    let handle = thread::spawn(|| {
        for i in 1..10 {
            println!("Spawned thread: {}", i);
            thread::sleep(Duration::from_millis(1));
        }
    });
    
    for i in 1..5 {
        println!("Main thread: {}", i);
        thread::sleep(Duration::from_millis(1));
    }
    
    handle.join().unwrap();  // 等待线程结束
}
```

### 传递数据到线程

```rust
use std::thread;

fn main() {
    let v = vec![1, 2, 3];
    
    // move 转移所有权
    let handle = thread::spawn(move || {
        println!("Vector: {:?}", v);
    });
    
    // println!("{:?}", v);  // 错误！v 已移动
    
    handle.join().unwrap();
}
```


## Send 和 Sync

### 概念

```rust
// Send: 可以跨线程转移所有权
// Sync: 可以跨线程共享引用 (&T 是 Send)

// 几乎所有类型都是 Send + Sync
// 例外：
// - Rc<T>: 非 Send，非 Sync
// - RefCell<T>: Send，非 Sync
// - *mut T (裸指针): 非 Send，非 Sync
```

### 为什么 Rc 不是 Send？

```rust
use std::rc::Rc;
use std::thread;

fn main() {
    let rc = Rc::new(5);
    
    // 编译错误！
    // thread::spawn(move || {
    //     println!("{}", rc);
    // });
    
    // Rc 的引用计数不是原子的
    // 多线程同时修改会导致数据竞争
}
```


## Arc (原子引用计数)

### 共享只读数据

```rust
use std::sync::Arc;
use std::thread;

fn main() {
    let data = Arc::new(vec![1, 2, 3]);
    
    let mut handles = vec![];
    
    for i in 0..3 {
        let data = Arc::clone(&data);  // 增加引用计数
        handles.push(thread::spawn(move || {
            println!("Thread {}: {:?}", i, data);
        }));
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
}
```


## Mutex (互斥锁)

### 基本用法

```rust
use std::sync::Mutex;

fn main() {
    let m = Mutex::new(5);
    
    {
        let mut num = m.lock().unwrap();  // 获取锁
        *num = 6;
    }  // 锁自动释放
    
    println!("m = {:?}", m);
}
```

### 跨线程共享

```rust
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];
    
    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            let mut num = counter.lock().unwrap();
            *num += 1;
        }));
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("Result: {}", *counter.lock().unwrap());  // 10
}
```

### RwLock (读写锁)

```rust
use std::sync::RwLock;

fn main() {
    let lock = RwLock::new(5);
    
    // 多个读操作可以并行
    {
        let r1 = lock.read().unwrap();
        let r2 = lock.read().unwrap();
        println!("{} {}", *r1, *r2);
    }
    
    // 写操作独占
    {
        let mut w = lock.write().unwrap();
        *w = 6;
    }
}
```


## Channel (通道)

### mpsc (多生产者单消费者)

```rust
use std::sync::mpsc;
use std::thread;

fn main() {
    let (tx, rx) = mpsc::channel();
    
    thread::spawn(move || {
        tx.send(String::from("Hello")).unwrap();
    });
    
    let received = rx.recv().unwrap();  // 阻塞等待
    println!("Got: {}", received);
}
```

### 多个生产者

```rust
use std::sync::mpsc;
use std::thread;

fn main() {
    let (tx, rx) = mpsc::channel();
    
    for i in 0..3 {
        let tx = tx.clone();
        thread::spawn(move || {
            tx.send(format!("Message from {}", i)).unwrap();
        });
    }
    
    drop(tx);  // 关闭原始发送端
    
    for received in rx {  // 迭代直到所有发送端关闭
        println!("Got: {}", received);
    }
}
```

### 同步通道

```rust
use std::sync::mpsc;

fn main() {
    // 有界通道，buffer = 1
    let (tx, rx) = mpsc::sync_channel(1);
    
    tx.send(1).unwrap();
    // tx.send(2).unwrap();  // 阻塞，直到有人接收
    
    println!("{}", rx.recv().unwrap());
}
```


## async/await

### 基本语法

```rust
async fn hello() -> String {
    String::from("Hello, async!")
}

async fn main_async() {
    let result = hello().await;
    println!("{}", result);
}

// 使用 tokio 运行时
#[tokio::main]
async fn main() {
    main_async().await;
}
```

### 并发执行

```rust
use tokio::time::{sleep, Duration};

async fn task(id: u32) {
    println!("Task {} started", id);
    sleep(Duration::from_secs(1)).await;
    println!("Task {} completed", id);
}

#[tokio::main]
async fn main() {
    // 并发执行多个任务
    let handles: Vec<_> = (0..3)
        .map(|i| tokio::spawn(task(i)))
        .collect();
    
    for handle in handles {
        handle.await.unwrap();
    }
}
```

### tokio::select!

```rust
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    tokio::select! {
        _ = sleep(Duration::from_secs(1)) => {
            println!("1 second passed");
        }
        _ = sleep(Duration::from_secs(2)) => {
            println!("2 seconds passed");
        }
    }
    // 输出: 1 second passed
    // 第一个完成的分支被选中，其他被取消
}
```


## 实战场景

### Lab 1: 线程池模式

```rust
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

struct ThreadPool {
    workers: Vec<thread::JoinHandle<()>>,
    sender: mpsc::Sender<Job>,
}

impl ThreadPool {
    fn new(size: usize) -> Self {
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        
        let workers = (0..size)
            .map(|_| {
                let receiver = Arc::clone(&receiver);
                thread::spawn(move || loop {
                    let job = receiver.lock().unwrap().recv();
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                })
            })
            .collect();
        
        ThreadPool { workers, sender }
    }
    
    fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.sender.send(Box::new(f)).unwrap();
    }
}
```

### Lab 2: 并发 Web 请求

```rust
use tokio;

async fn fetch(url: &str) -> Result<String, reqwest::Error> {
    let body = reqwest::get(url).await?.text().await?;
    Ok(body)
}

#[tokio::main]
async fn main() {
    let urls = vec![
        "https://httpbin.org/get",
        "https://httpbin.org/ip",
    ];
    
    let futures: Vec<_> = urls.iter()
        .map(|url| fetch(url))
        .collect();
    
    let results = futures::future::join_all(futures).await;
    
    for (url, result) in urls.iter().zip(results) {
        match result {
            Ok(body) => println!("{}: {} bytes", url, body.len()),
            Err(e) => println!("{}: Error: {}", url, e),
        }
    }
}
```


## 常见陷阱

### ❌ 陷阱 1: 死锁

```rust
use std::sync::Mutex;

fn main() {
    let m1 = Mutex::new(1);
    let m2 = Mutex::new(2);
    
    // 线程 1: lock m1, then m2
    // 线程 2: lock m2, then m1
    // 死锁！
    
    // 解决：统一锁顺序
}
```

### ❌ 陷阱 2: 锁中毒

```rust
use std::sync::Mutex;

let m = Mutex::new(0);
let _ = std::panic::catch_unwind(|| {
    let mut guard = m.lock().unwrap();
    panic!("Poison the lock");
});

// 锁已中毒
assert!(m.lock().is_err());

// 恢复
let guard = m.lock().unwrap_or_else(|e| e.into_inner());
```

### ❌ 陷阱 3: async 中阻塞

```rust
// 错误：在 async 中使用阻塞操作
async fn bad() {
    std::thread::sleep(Duration::from_secs(1));  // 阻塞整个线程！
}

// 正确
async fn good() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

// 或使用 spawn_blocking
tokio::task::spawn_blocking(|| {
    std::thread::sleep(Duration::from_secs(1));
}).await;
```


## 深入阅读

**推荐资源：**
- [Rust Book - Concurrency](https://doc.rust-lang.org/book/ch16-00-concurrency.html)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Async Book](https://rust-lang.github.io/async-book/)

**相关章节：**
- [05 - Unsafe Rust](./05-unsafe.md) - 原子操作
- [06 - AOSP Rust](./06-android-rust.md) - Android 异步实践


## 下一步

[05 - Unsafe Rust](./05-unsafe.md) - 突破安全边界
