## 1.配置远程仓库  origin是远程仓库的别名 代替xxx.git的地址
```shell
 git remote add my_work git@gitee.com:sisyphus12/my_work.git
```

## 2.开始推送 
```shell
git push <远程主机名> <本地分支名>:<远程分支名>

git push my_work master:master
``` 
===如果不让推拉下然后推送
```shell
git pull --rebase origin master, 将gitee上的文件和本地库合并. git push origin master
``` 
## 3.使用git命令推送项目完成

====小提示===

==git push origin与git push -u origin master的区别
 
### git push -u origin master 
上面命令将本地的master分支推送到origin主机，同时指定origin为默认主机，
后面就可以不加任何参数使用git push了。 不带任何参数的git push，默认只推送当前分支，这叫做simple方式。
此外，还有一种matching方式，会推送所有有对应的远程分支的本地分支。
Git 2.0版本之前，默认采用matching方法，现在改为默认采用simple方式。

### 查看git的配置信息
* git config -l

## 常用命令
* git config --global user.email "sisyphus12@aliyun.com"
* git config --global user.name "sisyphus12"
---
* git add -A  提交所有变化
* git add -u  提交被修改(modified)和被删除(deleted)文件，不包括新文件(new)
* git add .  提交新文件(new)和被修改(modified)文件，不包括被删除(deleted)文件
---
* git commit -a -m "add"：一次性把暂存区的所有修改提交到分支, -a 参数就是可以把还没有执行add命令的修改一起提交
* git remote -v 查看本地存储的远程仓库信息 
* git checkout dev 从当前分支切换到‘dev’分支
    1. -b 'dev' 建立并切换新分支 
* git rev-parse --abbrev-ref master@{upstream} 查看主分支对应的远程分支
* git symbolic-ref -q --short HEAD 查看当前分支名
* git branch 查看本地分支
    1. -d <branchname> //删除本地分支 
    2. -m //重命名本地分支 
    3. -r //查看远程所有分支 
    4. -a //查看所有分支
    5. -vv 查看当前详细分支信息（可看到当前分支与对应的远程追踪分支）
---
* git log --oneline -3 查看更改操作，只取其中三条
* git show (id) 查看提交的更改，id为 git log 显示的id 
---
## 远程分支与本地合并
* git pull = git fetch + git merge
* git fetch origin master:temp           #从远程的origin仓库的master分支下载到本地并新建一个分支temp

## 在解决冲突的时候文件覆盖
* git checkout --ours 文件路径              功能:我的覆盖别人的
* git checkout --theirs 文件路径            功能:别人的覆盖我的
---
* git reset --hard commit_id     //退到/进到 指定commit的sha码
----

## 分支合并


* git lfs install
* git lfs track "*.psd"
* git add .gitattributes
* git add file.psd
* git commit -m "Add design file"
* git push origin master
