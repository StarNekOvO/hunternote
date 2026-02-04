# Links

## Friends

<script setup>
import FriendCard from '/.vitepress/theme/components/FriendCard.vue'

const friends = [
  {
    name: 'Hikaru Lab',
    link: 'https://www.mengxiblog.top/',
    avatar: 'https://img-cn.static.isla.fan/2025/10/19/68f4824b7c228.png',
    desc: 'Web Engineer / CTFer. 即使是人造的记忆，也有它存在的价值',
    socialLinks: [
      { type: 'github', url: 'https://github.com/HikaruQwQ', name: 'GitHub' }
    ]
  },
  {
    name: '洛忆雨Yiur',
    link: 'https://www.yiurblog.top',
    avatar: 'https://www.yiurblog.top/head.jpg',
    desc: '无人相伴的路，惝恍迷离的舞',
    socialLinks: [
      { type: 'github', url: 'https://github.com/thisisluoyiyu', name: 'GitHub' },
      { type: 'bilibili', url: 'https://space.bilibili.com/159435471', name: 'Bilibili' },
      { type: 'telegram', url: 'https://t.me/Luo_yiyu', name: 'Telegram' }
    ]
  },
  {
    name: 'mintdesu',
    link: 'https://hoshiroko.com',
    avatar: 'https://api.hoshiroko.com/img/mint.jpg',
    desc: 'Yearning for companionship, longing for affection',
    socialLinks: [
      { type: 'github', url: 'https://github.com/mintdesu', name: 'GitHub' },
      { type: 'bilibili', url: 'https://space.bilibili.com/307514475', name: 'Bilibili' }
    ]
  },
  {
    name: '清凤小栈',
    link: 'https://清凤.fun',
    avatar: 'https://清凤.fun/images/logo/logo.webp',
    desc: '清凤和Kilock的温馨小屋',
    socialLinks: [
      { type: 'rss', url: 'https://清凤.fun/rss.xml', name: 'RSS' }
    ]
  },
  {
    name: 'hsn',
    link: 'https://www.zh314.xyz',
    avatar: '/img/hsn.png',
    desc: '手里两把锟斤拷，口中直呼烫烫烫',
    socialLinks: [
      { type: 'github', url: 'https://github.com/hsn8086', name: 'GitHub' },
      { type: 'twitter', url: 'https://twitter.com/hsn8086', name: 'Twitter' },
      { type: 'telegram', url: 'https://t.me/+QN71SuTbvAZlMmI1', name: 'Telegram' }
    ]
  },
  {
    name: '小小柳之絮',
    link: 'https://www.gymxbl.com',
    avatar: '/img/gymxbl.png',
    desc: '古之立大事者，不惟有超世之材，亦必有坚忍不拨之志',
    socialLinks: [
      { type: 'bilibili', url: 'https://space.bilibili.com/139186903', name: 'Bilibili' },
      { type: 'zhihu', url: 'https://www.zhihu.com/people/xiao-xiao-liu-zhi-xu', name: '知乎' }
    ]
  },
  {
    name: 'Xiaotian 7196',
    link: 'https://koten.top',
    avatar: 'https://koten.top/ISEKAI.png',
    desc: '无论如何，请不要后悔与我相遇',
    socialLinks: [
      { type: 'github', url: 'https://github.com/xiaotian7196', name: 'GitHub' }
    ]
  },
  {
    name: '啊不都',
    link: 'https://www.oplog.cn',
    avatar: 'https://www.google.com/s2/favicons?sz=128&domain=www.oplog.cn',
    desc: 'Qexo 开发者 / Hexo 博主',
    socialLinks: [
      { type: 'github', url: 'https://github.com/am-abudu', name: 'GitHub' }
    ]
  },
  {
    name: '水碧枫',
    link: 'https://www.crystmaple.net',
    avatar: 'https://www.crystmaple.net/images/avatar.webp',
    desc: '提拉米苏、南瓜派与红茶',
    socialLinks: [
      { type: 'github', url: 'https://github.com/CrystMaple', name: 'GitHub' },
      { type: 'bilibili', url: 'https://space.bilibili.com/1139519970', name: 'Bilibili' }
    ]
  },
  {
    name: '秋奈Akina',
    link: 'https://akinachan.com',
    avatar: '/img/10042.jpg',
    desc: ''
  },
  {
    name: '柒鸟',
    link: 'https://www.one-among.us/profile/SevenBird',
    avatar: '/img/sevenbird.jpg',
    desc: 'R.I.P.'
  }
]
</script>

<div class="friends-grid">
  <FriendCard
    v-for="friend in friends"
    :key="friend.link"
    :name="friend.name"
    :link="friend.link"
    :avatar="friend.avatar"
    :desc="friend.desc"
    :social-links="friend.socialLinks"
  />
</div>

<style>
.friends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 3rem 1.5rem;
  margin-top: 3rem;
  padding-top: 1rem;
}

@media (max-width: 640px) {
  .friends-grid {
    grid-template-columns: 1fr;
    gap: 3.5rem 1rem;
  }
}
</style>

