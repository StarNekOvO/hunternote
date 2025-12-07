# 友链

## Friends

<div class="friends-list">
  <div class="friend-item">
    <a href="https://blog.yuban.tech" target="_blank" rel="noopener noreferrer">
      <div class="friend-name">小柒</div>
      <div class="friend-url">blog.yuban.tech</div>
    </a>
  </div>

  <div class="friend-item">
    <a href="https://www.gymxbl.com" target="_blank" rel="noopener noreferrer">
      <div class="friend-name">小小柳之絮</div>
      <div class="friend-url">www.gymxbl.com</div>
    </a>
  </div>

  <div class="friend-item">
    <a href="https://xiaotian7196.github.io" target="_blank" rel="noopener noreferrer">
      <div class="friend-name">XIAOTIAN7196</div>
      <div class="friend-url">xiaotian7196.github.io</div>
    </a>
  </div>

  <div class="friend-item">
    <a href="https://www.mis1042.com" target="_blank" rel="noopener noreferrer">
      <div class="friend-name">Misaka10042</div>
      <div class="friend-url">www.mis1042.com</div>
    </a>
  </div>

  <div class="friend-item">
    <a href="https://www.oplog.cn" target="_blank" rel="noopener noreferrer">
      <div class="friend-name">啊不都</div>
      <div class="friend-url">www.oplog.cn</div>
    </a>
  </div>

  <div class="friend-item">
    <a href="https://www.crystmaple.net" target="_blank" rel="noopener noreferrer">
      <div class="friend-name">水碧枫的甜点屋</div>
      <div class="friend-url">www.crystmaple.net</div>
    </a>
  </div>
</div>

<style>
.friends-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1.5rem;
  margin-top: 2rem;
}

.friend-item {
  background: var(--vp-c-bg-soft);
  border-radius: 8px;
  padding: 1.5rem;
  transition: all 0.3s ease;
  border: 1px solid var(--vp-c-divider);
}

.friend-item:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
  border-color: var(--vp-c-brand);
}

.friend-item a {
  text-decoration: none;
  color: inherit;
  display: block;
}

.friend-name {
  font-size: 1.2rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  margin-bottom: 0.5rem;
}

.friend-url {
  font-size: 0.9rem;
  color: var(--vp-c-text-2);
  word-break: break-all;
}

.friend-item:hover .friend-name {
  color: var(--vp-c-brand);
}

@media (max-width: 768px) {
  .friends-list {
    grid-template-columns: 1fr;
  }
}
</style>

