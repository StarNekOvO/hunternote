# 02 - 集合框架

Java 数据结构：List、Set、Map、队列。

---

## 概念速览

**为什么需要集合框架？**
- 数组固定长度，不够灵活
- 不同场景需要不同数据结构
- 统一接口，便于替换实现

**集合层次结构：**

```
                    Iterable
                       │
                   Collection
            ┌──────────┼──────────┐
           List       Set       Queue
            │          │          │
      ┌─────┼─────┐ ┌──┼──┐    ┌──┼──┐
  ArrayList  │  Vector  │ TreeSet  PriorityQueue
        LinkedList  HashSet
        
                    Map
            ┌────────┼────────┐
        HashMap  TreeMap  LinkedHashMap
```

---

## List (有序可重复)

### ArrayList vs LinkedList

```java
// ArrayList: 动态数组
List<String> arrayList = new ArrayList<>();
arrayList.add("A");
arrayList.add("B");
arrayList.get(0);  // O(1) 随机访问

// LinkedList: 双向链表
List<String> linkedList = new LinkedList<>();
linkedList.add("A");
linkedList.addFirst("B");  // O(1) 头插
```

| 操作 | ArrayList | LinkedList |
|------|-----------|------------|
| 随机访问 | O(1) | O(n) |
| 头部插入 | O(n) | O(1) |
| 尾部插入 | O(1) 摊销 | O(1) |
| 内存占用 | 较少 | 较多 |

> [!TIP]
> 大多数情况使用 `ArrayList`，只有频繁头部操作时用 `LinkedList`。

### 常用操作

```java
List<Integer> list = new ArrayList<>();

// 添加
list.add(1);
list.add(0, 2);  // 插入到索引 0
list.addAll(Arrays.asList(3, 4, 5));

// 访问
int first = list.get(0);
int size = list.size();
boolean contains = list.contains(3);
int index = list.indexOf(3);

// 修改
list.set(0, 10);

// 删除
list.remove(0);         // 按索引
list.remove(Integer.valueOf(3));  // 按值

// 遍历
for (int n : list) { ... }
list.forEach(n -> System.out.println(n));

// 转换
Integer[] arr = list.toArray(new Integer[0]);
List<Integer> copy = new ArrayList<>(list);
```

---

## Set (无序不重复)

### HashSet vs TreeSet

```java
// HashSet: 哈希表，无序
Set<String> hashSet = new HashSet<>();
hashSet.add("B");
hashSet.add("A");
hashSet.add("C");
// 遍历顺序不确定

// TreeSet: 红黑树，有序
Set<String> treeSet = new TreeSet<>();
treeSet.add("B");
treeSet.add("A");
treeSet.add("C");
// 遍历: A, B, C (自然排序)

// LinkedHashSet: 保持插入顺序
Set<String> linkedSet = new LinkedHashSet<>();
```

| 特性 | HashSet | TreeSet | LinkedHashSet |
|------|---------|---------|---------------|
| 顺序 | 无 | 排序 | 插入顺序 |
| 增删查 | O(1) | O(log n) | O(1) |
| null | 允许 | 不允许 | 允许 |

### 去重示例

```java
List<Integer> numbers = Arrays.asList(1, 2, 2, 3, 3, 3);
Set<Integer> unique = new HashSet<>(numbers);
System.out.println(unique);  // [1, 2, 3]
```

---

## Map (键值对)

### HashMap

```java
Map<String, Integer> map = new HashMap<>();

// 添加
map.put("apple", 1);
map.put("banana", 2);

// 获取
int value = map.get("apple");        // 1
int def = map.getOrDefault("orange", 0);  // 0

// 检查
boolean hasKey = map.containsKey("apple");
boolean hasValue = map.containsValue(1);

// 删除
map.remove("banana");

// 遍历
for (Map.Entry<String, Integer> entry : map.entrySet()) {
    System.out.println(entry.getKey() + ": " + entry.getValue());
}

map.forEach((k, v) -> System.out.println(k + ": " + v));

// 只遍历键或值
for (String key : map.keySet()) { ... }
for (int val : map.values()) { ... }
```

### 常用 Map 操作 (Java 8+)

```java
// compute 系列
map.compute("apple", (k, v) -> v == null ? 1 : v + 1);
map.computeIfAbsent("grape", k -> 0);
map.computeIfPresent("apple", (k, v) -> v + 1);

// merge
map.merge("apple", 1, Integer::sum);  // 计数器

// 替换
map.replace("apple", 10);
map.replaceAll((k, v) -> v * 2);
```

### HashMap 实现原理

```
┌─────────────────────────────────────────────┐
│ Bucket Array (size = 16 默认)               │
├─────┬─────┬─────┬─────┬─────┬─────┬─────┬───┤
│  0  │  1  │  2  │  3  │  4  │ ... │ 15  │   │
└──│──┴─────┴──│──┴─────┴─────┴─────┴─────┴───┘
   ↓           ↓
 Entry      Entry → Entry → Entry  (链表/红黑树)
```

- 默认负载因子 0.75
- 链表长度 > 8 转红黑树 (Java 8+)
- 容量总是 2 的幂

---

## 队列

### Queue 和 Deque

```java
// Queue: 先进先出
Queue<String> queue = new LinkedList<>();
queue.offer("A");     // 入队
queue.offer("B");
String head = queue.poll();  // 出队: A
String peek = queue.peek();  // 查看队首: B

// Deque: 双端队列
Deque<String> deque = new ArrayDeque<>();
deque.offerFirst("A");
deque.offerLast("B");
deque.pollFirst();  // A
deque.pollLast();   // B

// 用 Deque 作为栈
Deque<String> stack = new ArrayDeque<>();
stack.push("A");
stack.push("B");
stack.pop();  // B
```

### PriorityQueue

```java
// 最小堆
PriorityQueue<Integer> minHeap = new PriorityQueue<>();
minHeap.offer(3);
minHeap.offer(1);
minHeap.offer(2);
System.out.println(minHeap.poll());  // 1

// 最大堆
PriorityQueue<Integer> maxHeap = new PriorityQueue<>(
    Collections.reverseOrder()
);
```

---

## Stream API (Java 8+)

### 基本操作

```java
List<Integer> numbers = Arrays.asList(1, 2, 3, 4, 5, 6);

// 过滤
List<Integer> evens = numbers.stream()
    .filter(n -> n % 2 == 0)
    .collect(Collectors.toList());  // [2, 4, 6]

// 映射
List<Integer> doubled = numbers.stream()
    .map(n -> n * 2)
    .collect(Collectors.toList());  // [2, 4, 6, 8, 10, 12]

// 归约
int sum = numbers.stream()
    .reduce(0, Integer::sum);  // 21

// 统计
long count = numbers.stream().count();
int max = numbers.stream().max(Integer::compare).orElse(0);
```

### 常用操作

```java
List<String> names = Arrays.asList("Alice", "Bob", "Charlie", "Alice");

// 去重
List<String> unique = names.stream()
    .distinct()
    .collect(Collectors.toList());

// 排序
List<String> sorted = names.stream()
    .sorted()
    .collect(Collectors.toList());

// 限制和跳过
List<String> limited = names.stream()
    .skip(1)
    .limit(2)
    .collect(Collectors.toList());

// 分组
Map<Integer, List<String>> byLength = names.stream()
    .collect(Collectors.groupingBy(String::length));

// 分区
Map<Boolean, List<String>> partitioned = names.stream()
    .collect(Collectors.partitioningBy(s -> s.length() > 3));

// 连接字符串
String joined = names.stream()
    .collect(Collectors.joining(", "));  // "Alice, Bob, Charlie, Alice"
```

---

## 实战场景

### Lab 1: 单词计数

```java
String text = "apple banana apple cherry banana apple";
String[] words = text.split(" ");

Map<String, Long> counts = Arrays.stream(words)
    .collect(Collectors.groupingBy(
        w -> w,
        Collectors.counting()
    ));

System.out.println(counts);
// {apple=3, banana=2, cherry=1}
```

### Lab 2: TopK 问题

```java
// 找出频率最高的 K 个元素
public List<Integer> topK(int[] nums, int k) {
    Map<Integer, Long> freq = Arrays.stream(nums)
        .boxed()
        .collect(Collectors.groupingBy(n -> n, Collectors.counting()));
    
    return freq.entrySet().stream()
        .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
        .limit(k)
        .map(Map.Entry::getKey)
        .collect(Collectors.toList());
}
```

### Lab 3: LRU Cache

```java
public class LRUCache<K, V> extends LinkedHashMap<K, V> {
    private final int capacity;
    
    public LRUCache(int capacity) {
        super(capacity, 0.75f, true);  // accessOrder = true
        this.capacity = capacity;
    }
    
    @Override
    protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
        return size() > capacity;
    }
}

LRUCache<String, Integer> cache = new LRUCache<>(3);
cache.put("a", 1);
cache.put("b", 2);
cache.put("c", 3);
cache.get("a");     // 访问 a
cache.put("d", 4);  // 淘汰 b (最久未使用)
```

---

## 常见陷阱

### ❌ 陷阱 1: ConcurrentModificationException

```java
List<String> list = new ArrayList<>(Arrays.asList("a", "b", "c"));

// 错误
for (String s : list) {
    if (s.equals("b")) {
        list.remove(s);  // ConcurrentModificationException
    }
}

// 正确 1: 使用 Iterator
Iterator<String> it = list.iterator();
while (it.hasNext()) {
    if (it.next().equals("b")) {
        it.remove();
    }
}

// 正确 2: removeIf (Java 8+)
list.removeIf(s -> s.equals("b"));
```

### ❌ 陷阱 2: 可变对象作为 Map 键

```java
List<String> key = new ArrayList<>();
key.add("a");

Map<List<String>, Integer> map = new HashMap<>();
map.put(key, 1);

key.add("b");  // 修改了键！
map.get(key);  // null! hashCode 变了
```

### ❌ 陷阱 3: Arrays.asList 的坑

```java
List<String> list = Arrays.asList("a", "b", "c");
// list.add("d");  // UnsupportedOperationException
// 返回的是固定大小的 List

// 正确
List<String> mutableList = new ArrayList<>(Arrays.asList("a", "b", "c"));
```

---

## 深入阅读

**推荐资源：**
- [Java Collections Framework](https://docs.oracle.com/javase/tutorial/collections/)
- [Stream API](https://docs.oracle.com/javase/tutorial/collections/streams/)

**相关章节：**
- [03 - 并发编程](./03-concurrency.md) - 并发集合
- [00 - 基础语法](./00-basics.md) - 数组基础

---

## 下一步

[03 - 并发编程](./03-concurrency.md) - 多线程与同步
