##搭建
apt install nfs-kernel-server
##配置文件
####/etc/exports文件的内容如下：

/tmp *(rw,sync,no_subtree_check,no_root_squash)

/data *(rw,sync,no_subtree_check,no_root_squash)

/logs *(rw,sync,no_subtree_check,no_root_squash)

##常用命令
service nfs-kernel-server restart
exportfs -rv
nfsstat
rpcinfo
sudo showmount -e localhost

##挂载共享目录
sudo mount -t nfs 192.168.3.167:/data /mnt/data

##优化
###1.调整读写缓冲区大小
  cat >>/etc/sysctl.conf<<EOF
  net.core.rmem_default = 8388608
  # 默认接收缓冲区大小为124928
  net.core.wmem_default = 8388608
  # 默认发送缓冲区大小为124928
  net.core.rmem_max = 16777216
  # 默认最大接收缓冲区大小为124828
  net.core.wmem_max = 16777216
  # 默认最大发送缓冲区大小为124928
  EOF

  sysctl -p

### 修改/etc/sysctl.conf后需要通过sysctl -p命令会同步到/proc/sys/net/core/下相应的文件去,让配置生效
### 也可直接修改/proc/sys/net/core/下相应的文件，但开机重启会失效

###2.nfsd的个数
缺省的系统在启动时，有8个nfsd进程
ps -efl|grep nfsd
通过查看/proc/net/rpc/nfsd文件的th行，第一个是nfsd的个数，后十个是线程是用的时间数，第二个到第四个值如果很大，那么就需要增加nfsd的个数。
具体如下：

vi /etc/init.d/nfs

找到RPCNFSDCOUNT,修改该值，一般和client端数目一致。

service nfs restart
mount -a


###3.挂载时优化参数
timeo：　　如果超时，客户端等待的时间，以十分之一秒计算
retrans：　超时尝试的次数。
bg：　　　 后台挂载，很有用
hard：　　 如果server端没有响应，那么客户端一直尝试挂载
wsize：　　写块大小
rsize：　　读块大小
intr：　　 可以中断不成功的挂载
noatime：　不更新文件的inode访问时间，可以提高速度
async：　　异步读写

intr: 默认情况下，当一个nfs 变得不可达后，在这个挂载点上的操作如ls、cd等会hang住。指定这个参数后，ls/cd之类的命令会收到信号EINTR 从而退出。
soft: 默认情况下，如果nfs server断开了，client这端会不停的尝试重新恢复连接而不是断开，这样频繁的重试会导致系统hang住,但是为啥就不知道了。指定soft后，client会timeout抛出异常而不是一直傻试。

mount 加上noatime参数

mount -t nfs 192.168.1.220:/mnt/nfs /mnt/nfs_t -o nolock, rsize=1024,wsize=1024,timeo=15


###开机挂载
vi /etc/fstab 
nfs-server-ip:/nfs1 /mnt/nfs1 nfs rsize=8192,wsize=8192 0 0 
