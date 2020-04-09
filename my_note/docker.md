## 镜像加速
```shell
    sudo mkdir -p /etc/docker
    sudo tee /etc/docker/daemon.json <<-'EOF'
    {
      "registry-mirrors": ["https://0jcgydcs.mirror.aliyuncs.com"]
    }
    EOF
    sudo systemctl daemon-reload
    sudo systemctl restart docker
```
## 拉取
    docker pull ubuntu

## 启动
    docker run -it ubuntu /bin/bash

## 后台
*    -d： 指定容器的运行模式。
*    -i: 交互式操作
*    -t: 终端。
*    ubuntu:15.10: 这是指用 ubuntu 15.10 版本镜像为基础来启动容器。
*    /bin/bash：放在镜像名后的是命令，这里我们希望有个交互式 Shell，因此用的是 /bin/bash。
docker run -itd --name ubuntu:15.10 ubuntu /bin/bash

## 特权级别运行
docker run  -p 22000:22 -p 30000:3000 --privileged=true  -v ~/work_dir/docker/ubuntu_p4_9.0:/root/bf-sde-9.1.0 -id --name=p4_9.1 ubuntu  /bin/bash

## 删除
     docker rmi 
## 查看磁盘占用情况
     docker system df 查看磁盘占

## 直接删除所有镜像
docker rmi `docker images -q`

按条件筛选之后删除镜像 docker rmi `docker images | grep xxxxx | awk '{print $3}'`

## 创建容器
     docker run -itd --name=my_docker_name ubuntu /bin/bash
## 进入容器
    docker  exec -it my_docker_name   /bin/bash   

## 查看容器信息
    docker inspect my_docker_name

## 数据卷
    docker run -it -v /test:/soft centos /bin/bash
    docker run -it -v --volumes-from c2 centos

## 修改镜像保存
    docker commit -m "Configured" webapp [新docker_name]
    docker commit -m "my apache" a404c6c174a2  mymysql:v1 
    sudo docker save -o ./webapp-1.0.tar webapp:1.0

    docker load -i webapp-1.0.tar

# Dockerfile 的结构

总体上来说，我们可以将 Dockerfile 理解为一个由上往下执行指令的脚本文件。当我们调用构建命令让 Docker 通过我们给出的 Dockerfile 构建镜像时，Docker 会逐一按顺序解析 Dockerfile 中的指令，并根据它们不同的含义执行不同的操作。

如果进行细分，我们可以将 Dockerfile 的指令简单分为五大类。

*   **基础指令**：用于定义新镜像的基础和性质。
*   **控制指令**：是指导镜像构建的核心部分，用于描述镜像在构建过程中需要执行的命令。
*   **引入指令**：用于将外部文件直接引入到构建镜像内部。
*   **执行指令**：能够为基于镜像所创建的容器，指定在启动时需要执行的脚本或命令。
*   **配置指令**：对镜像以及基于镜像所创建的容器，可以通过配置指令对其网络、用户等内容进行配置。

这五类命令并非都会出现在一个 Dockerfile 里，但却对基于这个 Dockerfile 所构建镜像形成不同的影响。

## 常见 Dockerfile 指令

熟悉 Dockerfile 的指令是编写 Dockerfile 的前提，这里我们先来介绍几个最常见的 Dockerfile 指令，它们基本上囊括了所有 Dockerfile 中 90% 以上的工作。

### FROM

通常来说，我们不会从零开始搭建一个镜像，而是会选择一个已经存在的镜像作为我们新镜像的基础，这种方式能够大幅减少我们的时间。

在 Dockerfile 里，我们可以通过 FROM 指令指定一个基础镜像，接下来所有的指令都是基于这个镜像所展开的。在镜像构建的过程中，Docker 也会先获取到这个给出的基础镜像，再从这个镜像上进行构建操作。

FROM 指令支持三种形式，不管是哪种形式，其核心逻辑就是指出能够被 Docker 识别的那个镜像，好让 Docker 从那个镜像之上开始构建工作。

```
FROM <image> [AS <name>]
FROM <image>[:<tag>] [AS <name>]
FROM <image>[@<digest>] [AS <name>]

```

既然选择一个基础镜像是构建新镜像的根本，那么 Dockerfile 中的第一条指令必须是 FROM 指令，因为没有了基础镜像，一切构建过程都无法开展。

当然，一个 Dockerfile 要以 FROM 指令作为开始并不意味着 FROM 只能是 Dockerfile 中的第一条指令。在 Dockerfile 中可以多次出现 FROM 指令，当 FROM 第二次或者之后出现时，表示在此刻构建时，要将当前指出镜像的内容合并到此刻构建镜像的内容里。这对于我们直接合并两个镜像的功能很有帮助。

### RUN

镜像的构建虽然是按照指令执行的，但指令只是引导，最终大部分内容还是控制台中对程序发出的命令，而 RUN 指令就是用于向控制台发送命令的指令。

在 RUN 指令之后，我们直接拼接上需要执行的命令，在构建时，Docker 就会执行这些命令，并将它们对文件系统的修改记录下来，形成镜像的变化。

```
RUN <command>
RUN ["executable", "param1", "param2"]

```

RUN 指令是支持 \\ 换行的，如果单行的长度过长，建议对内容进行切割，方便阅读。而事实上，我们会经常看到 \\ 分割的命令，例如在上面我们贴出的 Redis 镜像的 Dockerfile 里。

### ENTRYPOINT 和 CMD

基于镜像启动的容器，在容器启动时会根据镜像所定义的一条命令来启动容器中进程号为 1 的进程。而这个命令的定义，就是通过 Dockerfile 中的 ENTRYPOINT 和 CMD 实现的。

```
ENTRYPOINT ["executable", "param1", "param2"]
ENTRYPOINT command param1 param2

CMD ["executable","param1","param2"]
CMD ["param1","param2"]
CMD command param1 param2

```

ENTRYPOINT 指令和 CMD 指令的用法近似，都是给出需要执行的命令，并且它们都可以为空，或者说是不在 Dockerfile 里指出。

当 ENTRYPOINT 与 CMD 同时给出时，CMD 中的内容会作为 ENTRYPOINT 定义命令的参数，最终执行容器启动的还是 ENTRYPOINT 中给出的命令。

关于 ENTRYPOINT 和 CMD 的更详细对比，在后一节里我们会提到。

### EXPOSE

在[第 9 节：为容器配置网络](https://juejin.im/book/5b7ba116e51d4556f30b476c/section/5b8381a56fb9a019ba684035)中，在未做特殊定义的前提下，我们直接连接容器网络，只能访问容器明确暴露的端口。而我们之前介绍的是在容器创建时通过选项来暴露这些端口。

由于我们构建镜像时更了解镜像中应用程序的逻辑，也更加清楚它需要接收和处理来自哪些端口的请求，所以在镜像中定义端口暴露显然是更合理的做法。

通过 EXPOSE 指令就可以为镜像指定要暴露的端口。

```
EXPOSE <port> [<port>/<protocol>...]

```

当我们通过 EXPOSE 指令配置了镜像的端口暴露定义，那么基于这个镜像所创建的容器，在被其他容器通过 `--link` 选项连接时，就能够直接允许来自其他容器对这些端口的访问了。

### VOLUME

在一些程序里，我们需要持久化一些数据，比如数据库中存储数据的文件夹就需要单独处理。在之前的小节里，我们提到可以通过数据卷来处理这些问题。

但使用数据卷需要我们在创建容器时通过 `-v` 选项来定义，而有时候由于镜像的使用者对镜像了解程度不高，会漏掉数据卷的创建，从而引起不必要的麻烦。

还是那句话，制作镜像的人是最清楚镜像中程序工作的各项流程的，所以它来定义数据卷也是最合适的。所以在 Dockerfile 里，提供了 VOLUME 指令来定义基于此镜像的容器所自动建立的数据卷。

```
VOLUME ["/data"]

```

在 VOLUME 指令中定义的目录，在基于新镜像创建容器时，会自动建立为数据卷，不需要我们再单独使用 `-v` 选项来配置了。

### COPY 和 ADD

在制作新的镜像的时候，我们可能需要将一些软件配置、程序代码、执行脚本等直接导入到镜像内的文件系统里，使用 COPY 或 ADD 指令能够帮助我们直接从宿主机的文件系统里拷贝内容到镜像里的文件系统中。

```
COPY [--chown=<user>:<group>] <src>... <dest>
ADD [--chown=<user>:<group>] <src>... <dest>

COPY [--chown=<user>:<group>] ["<src>",... "<dest>"]
ADD [--chown=<user>:<group>] ["<src>",... "<dest>"]

```

COPY 与 ADD 指令的定义方式完全一样，需要注意的仅是当我们的目录中存在空格时，可以使用后两种格式避免空格产生歧义。

对比 COPY 与 ADD，两者的区别主要在于 ADD 能够支持使用网络端的 URL 地址作为 src 源，并且在源文件被识别为压缩包时，自动进行解压，而 COPY 没有这两个能力。

虽然看上去 COPY 能力稍弱，但对于那些不希望源文件被解压或没有网络请求的场景，COPY 指令是个不错的选择。

## 构建镜像

在编写好 Dockerfile 之后，我们就可以构建我们所定义的镜像了，构建镜像的命令为 `docker build`。

```
$ sudo docker build ./webapp

```

`docker build` 可以接收一个参数，需要特别注意的是，这个参数为一个目录路径 ( 本地路径或 URL 路径 )，而并非 Dockerfile 文件的路径。在 `docker build` 里，这个我们给出的目录会作为构建的环境目录，我们很多的操作都是基于这个目录进行的。

例如，在我们使用 COPY 或是 ADD 拷贝文件到构建的新镜像时，会以这个目录作为基础目录。

在默认情况下，`docker build` 也会从这个目录下寻找名为 Dockerfile 的文件，将它作为 Dockerfile 内容的来源。如果我们的 Dockerfile 文件路径不在这个目录下，或者有另外的文件名，我们可以通过 `-f` 选项单独给出 Dockerfile 文件的路径。

```
$ sudo docker build -t webapp:latest -f ./webapp/a.Dockerfile ./webapp

```

当然，在构建时我们最好总是携带上 `-t` 选项，用它来指定新生成镜像的名称。

```
$ sudo docker build -t webapp:latest ./webapp

```