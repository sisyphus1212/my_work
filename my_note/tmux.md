按 Ctrl+b, ← - 选择左边的窗格
按 Ctrl+b, → - 选择右边的窗格
按 Ctrl+b, ↑ - 选择上边的窗格
按 Ctrl+b, ↓ - 选择下边的窗格
按 Ctrl+b, { - 来向左交换窗格
按 Ctrl+b, } - 来向右交换窗格
按 Ctrl+b, o - 切换到下一个窗格（从左到右，从上到下）
按 Ctrl+b, ; - 移动到先前活动的窗格

按 Ctrl+b, c 来创建一个新窗口。
按 Ctrl+b, n 移动到下一个窗口。
按 Ctrl+b, p 移动到上一个窗口。
按 Ctrl+b, 0 ~ Ctrl+b, 9 立即移动到特定窗口。
按 Ctrl+b, l 移动到先前选择的窗口

按 Ctrl+b, w 以交互方式选择当前窗口。

按 Ctrl+b, z 缩放窗格，并再次按下它使缩放窗格恢复原状。
按 Ctrl+b, r 清屏。

tmux a -t $session_name 进入已存在的session

Ctrl+b f 在多个window里搜索关键字

Ctrl+b :list-buffer 列出缓冲区目标
Ctrl+b = 选择性粘贴缓冲区
Ctrl+b :show-buffer 查看缓冲区内容

Ctrl+b :set mode-keys vi vi模式

Ctrl+b :join-pane -t $window_name 移动pane合并至某个window
Ctrl+b ! 移动pane至window

tmux list-windows
tmux ls
tmux a
Ctrl-b d 暂时退出

rename-window docker_test
rename-session 


配置:
set-option -g mouse on
setw -g mode-keys vi
unbind C-b
set -g prefix C-a
bind-key r send-keys -R \; clear-history
set -g history-limit 50000
