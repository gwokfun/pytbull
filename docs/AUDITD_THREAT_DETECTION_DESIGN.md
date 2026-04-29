# Linux Auditd-Based Threat Detection System Design

## 文档信息
- **版本**: 1.0
- **日期**: 2026-04-29
- **状态**: 设计方案
- **目标**: 基于Linux auditd实现本地主机威胁感知功能

---

## 1. 项目概述

### 1.1 背景与目标

本设计旨在基于Linux auditd框架，实现一个可配置、低代码的本地主机威胁检测系统。系统将实时采集和分析Linux系统的新增内容及异常事件，生成异常信息日志，为主机安全提供实时防护能力。

### 1.2 核心设计原则

1. **配置驱动**: 通过YAML/JSON配置文件定义检测规则，无需编写代码
2. **模块化设计**: 采用插件式架构，支持灵活扩展
3. **低代码实现**: 提供规则模板和DSL，减少开发工作量
4. **高性能**: 异步处理，避免影响系统性能
5. **可维护性**: 清晰的配置结构，便于后续维护和扩展

### 1.3 功能范围

#### 监控内容
- **进程活动**: 新进程创建、进程执行、进程终止
- **网络连接**: TCP/UDP连接建立、外部IP访问、端口监听
- **文件操作**: 敏感文件读写、配置文件修改、可执行文件变更
- **用户行为**: 用户登录、权限提升、sudo操作
- **系统调用**: 敏感系统调用监控（execve, connect, bind等）

#### 异常检测
- **公网IP访问**: 访问外部公网地址
- **资源异常**: CPU/内存占用过高的进程
- **黑名单软件**: 已知恶意软件或违规软件
- **内网扫描**: 频繁的端口扫描或网络探测行为
- **异常登录**: 非工作时间登录、异常来源登录
- **权限滥用**: 未授权的权限提升操作
- **数据外泄**: 大量数据传输到外部IP

---

## 2. 系统架构设计

### 2.1 总体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Threat Detection System                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────┐      ┌──────────────────┐                 │
│  │  Web Dashboard  │◄────►│  Report Engine   │                 │
│  │   (Optional)    │      │   (HTML/JSON)    │                 │
│  └─────────────────┘      └──────────────────┘                 │
│           ▲                         ▲                            │
│           │                         │                            │
│           └─────────┬───────────────┘                            │
│                     │                                            │
│           ┌─────────▼─────────┐                                 │
│           │   Alert Manager   │                                 │
│           │  - Aggregation    │                                 │
│           │  - Deduplication  │                                 │
│           │  - Notification   │                                 │
│           └─────────▲─────────┘                                 │
│                     │                                            │
│  ┌──────────────────┴──────────────────┐                        │
│  │        Detection Engine             │                        │
│  │  ┌────────────────────────────┐    │                        │
│  │  │   Rule Engine              │    │                        │
│  │  │  - Condition Evaluator     │    │                        │
│  │  │  - Context Enrichment      │    │                        │
│  │  │  - Threshold Detection     │    │                        │
│  │  └────────────────────────────┘    │                        │
│  │  ┌────────────────────────────┐    │                        │
│  │  │   Correlation Engine       │    │                        │
│  │  │  - Event Aggregation       │    │                        │
│  │  │  - Pattern Matching        │    │                        │
│  │  │  - Behavioral Analysis     │    │                        │
│  │  └────────────────────────────┘    │                        │
│  └─────────────────▲───────────────────┘                        │
│                    │                                             │
│  ┌─────────────────┴───────────────────┐                        │
│  │     Event Processing Layer          │                        │
│  │  ┌────────────┐  ┌──────────────┐  │                        │
│  │  │  Parser    │  │  Normalizer  │  │                        │
│  │  │  - Auditd  │  │  - Timestamp │  │                        │
│  │  │  - Syslog  │  │  - Fields    │  │                        │
│  │  │  - Custom  │  │  - Enrichment│  │                        │
│  │  └────────────┘  └──────────────┘  │                        │
│  └─────────────────▲───────────────────┘                        │
│                    │                                             │
│  ┌─────────────────┴───────────────────┐                        │
│  │       Data Collection Layer         │                        │
│  │  ┌───────────┐  ┌──────────────┐   │                        │
│  │  │  Auditd   │  │   /proc      │   │                        │
│  │  │  Collector│  │   Monitor    │   │                        │
│  │  └───────────┘  └──────────────┘   │                        │
│  │  ┌───────────┐  ┌──────────────┐   │                        │
│  │  │  Netlink  │  │   System     │   │                        │
│  │  │  Monitor  │  │   Metrics    │   │                        │
│  │  └───────────┘  └──────────────┘   │                        │
│  └─────────────────────────────────────┘                        │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
          ▲                                       ▲
          │                                       │
  ┌───────┴────────┐                   ┌─────────┴─────────┐
  │  Audit Rules   │                   │  Detection Rules  │
  │  (auditd.rules)│                   │  (YAML Configs)   │
  └────────────────┘                   └───────────────────┘
```

### 2.2 核心组件说明

#### 2.2.1 数据采集层 (Data Collection Layer)

**Auditd Collector**
- 通过auditd框架采集系统审计事件
- 配置audit rules监控关键系统调用
- 实时读取audit.log文件

**Proc Monitor**
- 监控/proc文件系统获取进程信息
- 收集CPU、内存使用率
- 追踪进程树关系

**Netlink Monitor**
- 通过netlink socket监控网络连接
- 实时获取TCP/UDP连接状态
- 监控网络统计信息

**System Metrics**
- 收集系统级别的资源使用情况
- 监控磁盘I/O、网络流量
- 系统负载和性能指标

#### 2.2.2 事件处理层 (Event Processing Layer)

**Parser**
- 解析auditd日志格式
- 支持多种日志源（syslog、journald）
- 提取关键字段和元数据

**Normalizer**
- 标准化时间戳格式
- 统一字段命名
- 数据类型转换
- 上下文信息补充（进程名、用户名等）

#### 2.2.3 检测引擎 (Detection Engine)

**Rule Engine**
- 基于YAML配置的规则匹配
- 支持条件表达式（AND/OR/NOT）
- 阈值检测（频率、数量、时间窗口）
- 上下文信息丰富

**Correlation Engine**
- 跨事件关联分析
- 时间序列模式识别
- 行为基线建立
- 异常偏差检测

#### 2.2.4 告警管理 (Alert Manager)

- 告警聚合与去重
- 告警优先级排序
- 多渠道通知（日志文件、Syslog、Webhook）
- 告警抑制策略

#### 2.2.5 报告引擎 (Report Engine)

- 生成HTML/JSON格式报告
- 可视化统计图表
- 历史趋势分析
- 与现有pytbull报告系统集成

### 2.3 数据流

```
System Events
     │
     ▼
Auditd/Netlink/Proc
     │
     ▼
Raw Event Collection
     │
     ▼
Event Parsing & Normalization
     │
     ▼
Rule Matching & Correlation
     │
     ▼
Alert Generation
     │
     ├────► Log Files
     ├────► Database (SQLite)
     ├────► Real-time Dashboard
     └────► External Systems (Syslog/Webhook)
```

---

## 3. 配置驱动设计

### 3.1 配置文件结构

系统采用分层配置架构：

```
conf/
├── threat_detection.cfg        # 主配置文件
├── audit_rules/
│   ├── process.rules          # 进程监控规则
│   ├── network.rules          # 网络监控规则
│   ├── file.rules             # 文件监控规则
│   └── user.rules             # 用户行为规则
├── detection_rules/
│   ├── process_anomaly.yaml   # 进程异常检测
│   ├── network_anomaly.yaml   # 网络异常检测
│   ├── file_anomaly.yaml      # 文件异常检测
│   ├── resource_anomaly.yaml  # 资源异常检测
│   └── custom/                # 自定义规则目录
│       └── *.yaml
├── blacklists/
│   ├── ips.txt                # IP黑名单
│   ├── domains.txt            # 域名黑名单
│   ├── processes.txt          # 进程黑名单
│   └── files.txt              # 文件黑名单
└── templates/
    └── rule_template.yaml     # 规则模板
```

### 3.2 主配置文件格式

```yaml
# threat_detection.cfg
system:
  name: "Host Threat Detection System"
  version: "1.0"
  enable: true

data_collection:
  auditd:
    enable: true
    log_path: "/var/log/audit/audit.log"
    buffer_size: 8192
    follow_mode: true  # 实时跟踪日志

  proc_monitor:
    enable: true
    scan_interval: 5  # 秒
    metrics:
      - cpu
      - memory
      - network
      - io

  netlink:
    enable: true
    protocols:
      - tcp
      - udp
      - icmp

processing:
  workers: 4  # 处理线程数
  queue_size: 10000
  batch_size: 100
  flush_interval: 1  # 秒

detection:
  rule_dirs:
    - "conf/detection_rules"
    - "conf/detection_rules/custom"
  reload_interval: 60  # 秒，热加载规则

  correlation:
    enable: true
    time_window: 300  # 秒，关联时间窗口
    max_events: 1000

  baseline:
    enable: false  # 行为基线学习（可选）
    learning_period: 7  # 天

alerting:
  enable: true
  min_severity: "medium"  # low/medium/high/critical

  deduplication:
    enable: true
    time_window: 60  # 秒

  outputs:
    - type: file
      path: "/var/log/threat_detection/alerts.log"
      format: json

    - type: syslog
      enable: false
      host: "127.0.0.1"
      port: 514
      facility: "local0"

    - type: webhook
      enable: false
      url: "http://siem-server/api/alerts"
      method: POST
      headers:
        Authorization: "Bearer TOKEN"

  notification:
    email:
      enable: false
      smtp_server: "smtp.example.com"
      recipients:
        - "security@example.com"

reporting:
  enable: true
  output_dir: "report/threat_detection"
  formats:
    - html
    - json
  retention_days: 30

storage:
  database:
    type: sqlite
    path: "data/threat_detection.db"
    retention_days: 90

blacklists:
  enable: true
  auto_reload: true
  reload_interval: 300  # 秒
  files:
    ips: "conf/blacklists/ips.txt"
    domains: "conf/blacklists/domains.txt"
    processes: "conf/blacklists/processes.txt"
    files: "conf/blacklists/files.txt"

whitelists:
  enable: true
  files:
    ips: "conf/whitelists/ips.txt"
    processes: "conf/whitelists/processes.txt"

logging:
  level: INFO  # DEBUG/INFO/WARNING/ERROR
  file: "/var/log/threat_detection/system.log"
  max_size_mb: 100
  backup_count: 5
```

### 3.3 检测规则格式 (Detection Rules DSL)

#### 3.3.1 规则结构

```yaml
# conf/detection_rules/network_anomaly.yaml

# 规则元信息
rule_id: "NET-001"
name: "访问外部公网IP"
description: "检测系统进程访问外部公网IP地址"
category: "network"
severity: "medium"  # low/medium/high/critical
enabled: true
version: "1.0"
author: "Security Team"
created_at: "2026-04-29"
updated_at: "2026-04-29"

# 规则标签
tags:
  - network
  - external
  - internet

# 数据源
data_sources:
  - auditd
  - netlink

# 检测条件
conditions:
  # 事件类型过滤
  event_type: "SYSCALL"
  syscall:
    - "connect"
    - "sendto"

  # 字段匹配条件
  match:
    # 目标IP为公网IP
    dest_ip:
      type: "public_ip"
      exclude_ranges:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "127.0.0.0/8"

    # 进程不在白名单中
    process:
      not_in_whitelist: true
      exclude_patterns:
        - "^/usr/bin/apt"
        - "^/usr/bin/yum"
        - "^/usr/bin/wget"
        - "^/usr/bin/curl"

  # 逻辑表达式
  expression: "(event_type == 'SYSCALL') AND (syscall IN ['connect', 'sendto']) AND (dest_ip.is_public == true) AND (process.whitelisted == false)"

# 阈值检测（可选）
threshold:
  type: "frequency"  # frequency/count/rate
  count: 10
  time_window: 60  # 秒
  field: "dest_ip"  # 基于哪个字段计数

# 上下文丰富
enrichment:
  - type: "geoip"
    field: "dest_ip"
    output: "geo_info"

  - type: "process_tree"
    field: "pid"
    depth: 3

  - type: "user_info"
    field: "uid"

# 告警配置
alert:
  enabled: true
  title: "检测到访问外部公网IP"
  message: "进程 {process} (PID: {pid}) 由用户 {user} 访问外部IP {dest_ip}:{dest_port}"

  # 告警字段
  fields:
    - timestamp
    - hostname
    - user
    - pid
    - process
    - command_line
    - dest_ip
    - dest_port
    - geo_info

  # 响应动作（可选）
  actions:
    - type: "log"
      output: "alerts.log"

    - type: "syslog"
      priority: "warning"

    - type: "webhook"
      url: "http://siem/api/alert"

# 抑制规则（避免告警风暴）
suppression:
  enabled: true
  duration: 300  # 秒
  fields:
    - process
    - dest_ip
```

#### 3.3.2 更多规则示例

**进程异常检测**

```yaml
# conf/detection_rules/process_anomaly.yaml

---
rule_id: "PROC-001"
name: "黑名单进程启动"
description: "检测已知恶意进程或违规软件启动"
category: "process"
severity: "critical"
enabled: true

data_sources:
  - auditd

conditions:
  event_type: "EXECVE"

  match:
    process_name:
      in_blacklist: true
      blacklist_file: "conf/blacklists/processes.txt"

  # 也可以直接指定
  or_patterns:
    - "*/nc"
    - "*/ncat"
    - "*/netcat"
    - "*backdoor*"
    - "*rootkit*"

alert:
  enabled: true
  title: "检测到黑名单进程启动"
  message: "用户 {user} 启动了黑名单进程 {process} (PID: {pid})"
  severity: "critical"

---
rule_id: "PROC-002"
name: "高CPU占用进程"
description: "检测CPU占用异常高的进程"
category: "resource"
severity: "medium"
enabled: true

data_sources:
  - proc_monitor

conditions:
  metric_type: "cpu"

  threshold:
    cpu_percent: "> 80"
    duration: 60  # 持续时间（秒）

  exclude:
    processes:
      - "mysqld"
      - "java"
      - "node"

alert:
  enabled: true
  title: "检测到高CPU占用进程"
  message: "进程 {process} (PID: {pid}) CPU占用率为 {cpu_percent}%"

---
rule_id: "PROC-003"
name: "异常子进程创建"
description: "检测异常的父子进程关系"
category: "process"
severity: "high"
enabled: true

data_sources:
  - auditd

conditions:
  event_type: "EXECVE"

  # 父进程检查
  parent_process:
    patterns:
      - "httpd"
      - "nginx"
      - "apache2"

  # 子进程检查
  child_process:
    patterns:
      - "*/bin/bash"
      - "*/bin/sh"
      - "*/python"
      - "*/perl"
      - "*/nc"

correlation:
  enabled: true
  events:
    - type: "EXECVE"
      time_window: 10

alert:
  enabled: true
  title: "Web服务器产生异常子进程"
  message: "Web服务器 {parent_process} 创建了shell子进程 {child_process}"
```

**网络扫描检测**

```yaml
# conf/detection_rules/network_scanning.yaml

rule_id: "NET-002"
name: "内网端口扫描"
description: "检测对内网主机的频繁端口扫描行为"
category: "network"
severity: "high"
enabled: true

data_sources:
  - netlink
  - auditd

conditions:
  event_type: "SYSCALL"
  syscall: "connect"

  # 目标为内网IP
  match:
    dest_ip:
      type: "private_ip"
      ranges:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"

# 阈值：同一源主机在60秒内连接超过20个不同端口
threshold:
  type: "unique_count"
  field: "dest_port"
  group_by: "src_ip"
  count: 20
  time_window: 60

correlation:
  enabled: true
  pattern: "scan"
  indicators:
    - connection_failures: "> 80%"  # 大量连接失败
    - port_range_wide: true  # 端口范围广

alert:
  enabled: true
  title: "检测到内网端口扫描"
  message: "主机 {src_ip} 在 {time_window} 秒内扫描了 {unique_ports} 个端口"
  fields:
    - src_ip
    - dest_ip_list
    - port_list
    - scan_speed
```

**文件完整性监控**

```yaml
# conf/detection_rules/file_anomaly.yaml

rule_id: "FILE-001"
name: "敏感文件修改"
description: "监控系统关键文件的修改操作"
category: "file"
severity: "high"
enabled: true

data_sources:
  - auditd

conditions:
  event_type: "PATH"
  syscall:
    - "openat"
    - "open"
    - "write"
    - "rename"

  # 监控的文件路径
  match:
    file_path:
      patterns:
        - "/etc/passwd"
        - "/etc/shadow"
        - "/etc/sudoers"
        - "/etc/ssh/sshd_config"
        - "/etc/pam.d/*"
        - "/root/.ssh/*"
        - "/home/*/.ssh/*"
        - "/etc/cron*"
        - "/var/spool/cron/*"

  # 排除系统进程
  exclude:
    process:
      - "/usr/bin/passwd"
      - "/usr/sbin/useradd"
      - "/usr/sbin/usermod"

enrichment:
  - type: "file_hash"
    algorithm: "sha256"
  - type: "file_diff"
    keep_backup: true

alert:
  enabled: true
  title: "敏感文件被修改"
  message: "用户 {user} 通过进程 {process} 修改了敏感文件 {file_path}"

actions:
  - type: "backup"
    destination: "/var/log/threat_detection/file_backups"
  - type: "log"
    include_diff: true
```

**用户行为异常**

```yaml
# conf/detection_rules/user_anomaly.yaml

---
rule_id: "USER-001"
name: "异常时间登录"
description: "检测非工作时间的登录行为"
category: "user"
severity: "medium"
enabled: true

data_sources:
  - auditd

conditions:
  event_type: "USER_LOGIN"

  # 时间条件
  time:
    # 工作时间之外（周一至周五 9:00-18:00）
    working_hours:
      enabled: true
      weekdays: [1, 2, 3, 4, 5]
      start_time: "09:00"
      end_time: "18:00"
      alert_outside: true

  # 排除特定用户
  exclude:
    users:
      - "root"
      - "sysadmin"

alert:
  enabled: true
  title: "检测到非工作时间登录"
  message: "用户 {user} 在 {timestamp} 从 {src_ip} 登录系统"

---
rule_id: "USER-002"
name: "权限提升检测"
description: "监控sudo和su命令的使用"
category: "user"
severity: "high"
enabled: true

data_sources:
  - auditd

conditions:
  event_type: "EXECVE"

  match:
    process:
      patterns:
        - "/usr/bin/sudo"
        - "/bin/su"

    # 检测提升到root
    target_user: "root"

# 频率检测
threshold:
  type: "frequency"
  count: 5
  time_window: 300

alert:
  enabled: true
  title: "检测到权限提升操作"
  message: "用户 {user} 执行了权限提升命令: {command_line}"
```

### 3.4 Auditd规则配置

系统需要配置auditd规则来采集所需的系统事件：

```bash
# conf/audit_rules/process.rules
# 进程监控规则

# 监控所有进程执行
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# 监控进程终止
-a always,exit -F arch=b64 -S exit -S exit_group -k process_exit
-a always,exit -F arch=b32 -S exit -S exit_group -k process_exit
```

```bash
# conf/audit_rules/network.rules
# 网络监控规则

# 监控网络连接
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b32 -S connect -k network_connect

# 监控端口绑定
-a always,exit -F arch=b64 -S bind -k network_bind
-a always,exit -F arch=b32 -S bind -k network_bind

# 监控socket创建
-a always,exit -F arch=b64 -S socket -k network_socket
-a always,exit -F arch=b32 -S socket -k network_socket
```

```bash
# conf/audit_rules/file.rules
# 文件监控规则

# 监控敏感文件
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes

# 监控系统二进制文件
-w /usr/bin -p wa -k bin_changes
-w /usr/sbin -p wa -k sbin_changes
-w /bin -p wa -k bin_changes
-w /sbin -p wa -k sbin_changes

# 监控定时任务
-w /etc/cron.d -p wa -k cron_changes
-w /etc/cron.daily -p wa -k cron_changes
-w /etc/cron.hourly -p wa -k cron_changes
-w /var/spool/cron -p wa -k cron_changes
```

```bash
# conf/audit_rules/user.rules
# 用户行为监控规则

# 监控用户登录
-w /var/log/lastlog -p wa -k user_login
-w /var/run/utmp -p wa -k user_session
-w /var/log/wtmp -p wa -k user_session

# 监控权限提升
-a always,exit -F arch=b64 -S setuid -S setreuid -S setresuid -k privilege_escalation
-a always,exit -F arch=b32 -S setuid -S setreuid -S setresuid -k privilege_escalation

# 监控sudo使用
-w /etc/sudoers -p wa -k sudo_config
-w /var/log/sudo.log -p wa -k sudo_usage
```

---

## 4. 实施计划

### 4.1 开发阶段

#### 阶段1: 基础框架开发 (2周)

**目标**: 建立核心架构和数据采集能力

**任务**:
1. 创建项目目录结构
2. 实现配置文件解析器 (YAML/INI格式)
3. 开发auditd日志采集器
   - 实时tail日志文件
   - 解析audit日志格式
   - 事件队列管理
4. 实现proc文件系统监控器
   - 进程信息采集
   - 资源使用率统计
5. 开发netlink网络监控器
   - TCP/UDP连接监控
   - 连接状态追踪
6. 建立SQLite数据库schema
7. 实现基础日志记录功能

**交付物**:
- 可运行的数据采集框架
- 配置文件模板
- 单元测试

#### 阶段2: 检测引擎开发 (3周)

**目标**: 实现规则引擎和检测逻辑

**任务**:
1. 开发YAML规则解析器
   - 规则语法验证
   - 规则热加载机制
2. 实现条件匹配引擎
   - 字段匹配器
   - 正则表达式支持
   - 黑白名单检查
3. 开发阈值检测模块
   - 频率统计
   - 时间窗口管理
   - 计数器实现
4. 实现事件关联引擎
   - 多事件聚合
   - 时间序列分析
   - 模式匹配
5. 开发上下文丰富模块
   - GeoIP查询
   - 进程树构建
   - 用户信息补充
6. 创建内置检测规则库
   - 网络异常规则
   - 进程异常规则
   - 文件异常规则
   - 用户行为规则

**交付物**:
- 完整的检测引擎
- 规则配置文件
- 规则开发文档
- 集成测试

#### 阶段3: 告警与报告系统 (2周)

**目标**: 实现告警管理和报告生成

**任务**:
1. 开发告警管理器
   - 告警聚合
   - 去重逻辑
   - 优先级排序
2. 实现多渠道输出
   - 文件输出 (JSON/Plain)
   - Syslog集成
   - Webhook支持
3. 开发报告生成器
   - HTML报告模板
   - JSON数据导出
   - 统计图表生成
4. 集成到pytbull Web界面
   - 新增威胁检测页面
   - 告警列表展示
   - 实时监控面板

**交付物**:
- 告警系统
- 报告模板
- Web界面集成
- 用户手册

#### 阶段4: 优化与测试 (2周)

**目标**: 性能优化和全面测试

**任务**:
1. 性能优化
   - 异步处理优化
   - 内存使用优化
   - 日志采集性能调优
2. 全面测试
   - 功能测试
   - 性能测试
   - 压力测试
   - 边界条件测试
3. 文档完善
   - 安装部署文档
   - 配置说明文档
   - 规则开发指南
   - 故障排查指南
4. 安全加固
   - 权限检查
   - 输入验证
   - 防注入处理

**交付物**:
- 优化后的系统
- 完整测试报告
- 完整文档
- 安装包

### 4.2 部署阶段

#### 阶段5: 试点部署 (1周)

**任务**:
1. 选择2-3台测试主机
2. 安装部署系统
3. 配置基础检测规则
4. 观察系统运行
5. 收集反馈和问题

**交付物**:
- 部署报告
- 问题列表
- 优化建议

#### 阶段6: 生产部署 (2周)

**任务**:
1. 根据反馈优化系统
2. 编写自动化部署脚本
3. 批量部署到生产环境
4. 建立监控和告警
5. 培训运维团队

**交付物**:
- 自动化部署脚本
- 监控配置
- 运维手册
- 培训材料

### 4.3 运维阶段

#### 持续运维

**任务**:
1. 规则库维护
   - 根据新威胁更新规则
   - 优化误报规则
   - 添加自定义规则
2. 系统监控
   - 监控系统性能
   - 检查日志采集状态
   - 定期检查告警质量
3. 版本升级
   - 定期发布新版本
   - 功能增强
   - Bug修复

### 4.4 时间线

```
Week 1-2:  [====] 基础框架开发
Week 3-5:  [========] 检测引擎开发
Week 6-7:  [====] 告警与报告系统
Week 8-9:  [====] 优化与测试
Week 10:   [==] 试点部署
Week 11-12:[====] 生产部署
Week 13+:  [============================...] 持续运维
```

**总计**: 约12周完成开发和部署，第13周起进入持续运维

---

## 5. 技术栈选择

### 5.1 核心技术

**编程语言**: Python 3.8+
- 理由: 与pytbull现有技术栈保持一致，丰富的系统编程库

**数据采集**:
- `auditd`: Linux审计框架
- `pyinotify/inotify`: 文件系统监控
- `psutil`: 进程和系统信息
- `pynetlink/socket`: 网络监控

**数据处理**:
- `pyyaml`: YAML配置解析
- `jsonschema`: 配置验证
- `python-dateutil`: 时间处理
- `re/regex`: 正则表达式

**数据存储**:
- `sqlite3`: 轻量级数据库（已在pytbull中使用）
- 可选: `Redis`用于高性能缓存

**Web界面**:
- `CherryPy`: Web框架（已在pytbull中使用）
- `Jinja2`: HTML模板引擎
- `Chart.js/jqplot`: 图表库

### 5.2 外部依赖

**系统工具**:
```bash
# 必需
auditd          # 审计框架
python3         # Python运行时
sqlite3         # 数据库

# 可选（用于增强功能）
geoipupdate     # GeoIP数据库更新
```

**Python库**:
```python
# requirements.txt
pyyaml>=5.4
psutil>=5.8
configparser>=5.0
python-dateutil>=2.8
cherrypy>=18.6  # 已有
jinja2>=3.0
jsonschema>=3.2
requests>=2.26  # Webhook支持
```

### 5.3 性能考虑

**异步处理**:
- 使用`asyncio`或线程池处理事件
- 队列缓冲避免数据丢失
- 批量处理提高效率

**资源控制**:
- 限制内存使用（队列大小）
- 控制CPU使用率（处理线程数）
- 定期清理过期数据

**日志采集优化**:
- 使用`inotify`监控日志文件变化
- 增量读取避免重复处理
- 位置记录防止数据丢失

---

## 6. 系统集成

### 6.1 与Pytbull集成

**目录结构**:
```
pytbull/
├── pytbull                      # 主程序（扩展命令行参数）
├── modules/
│   └── threatDetection.py       # 新增威胁检测模块
├── classes/
│   ├── threat_detector.py       # 威胁检测核心类
│   ├── rule_engine.py           # 规则引擎
│   ├── event_collector.py       # 事件采集器
│   └── alert_manager.py         # 告警管理器
├── conf/
│   ├── threat_detection.cfg     # 威胁检测配置
│   ├── audit_rules/             # Audit规则目录
│   ├── detection_rules/         # 检测规则目录
│   └── blacklists/              # 黑名单目录
├── data/
│   └── threat_detection.db      # 威胁检测数据库
├── report/
│   └── threat_detection/        # 威胁检测报告目录
└── docs/
    └── THREAT_DETECTION.md      # 威胁检测文档
```

**命令行扩展**:
```bash
# 启动威胁检测
python pytbull --threat-detection start

# 停止威胁检测
python pytbull --threat-detection stop

# 查看状态
python pytbull --threat-detection status

# 重载规则
python pytbull --threat-detection reload

# 生成报告
python pytbull --threat-detection report

# 测试规则
python pytbull --threat-detection test-rule conf/detection_rules/network_anomaly.yaml
```

**Web界面扩展**:
- 新增"威胁检测"菜单
- 实时告警展示页面
- 检测规则管理页面
- 系统状态监控页面
- 报告查看页面

### 6.2 与SIEM系统集成

**Syslog集成**:
```python
# 告警通过syslog发送到SIEM
import syslog

syslog.openlog(facility=syslog.LOG_LOCAL0)
syslog.syslog(syslog.LOG_WARNING, alert_json)
```

**Webhook集成**:
```python
# POST告警到SIEM API
import requests

response = requests.post(
    siem_url,
    json=alert_data,
    headers={"Authorization": "Bearer TOKEN"}
)
```

**CEF格式支持**:
```python
# 生成CEF格式告警
# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
cef_format = f"CEF:0|MyCompany|ThreatDetection|1.0|{rule_id}|{alert_title}|{severity}|src={src_ip} dst={dst_ip} suser={user}"
```

---

## 7. 可维护性与扩展性

### 7.1 规则管理

**规则版本控制**:
- 所有规则文件纳入Git管理
- 规则变更需要code review
- 建立规则测试框架

**规则分类**:
```
detection_rules/
├── builtin/              # 内置规则（系统维护）
│   ├── network/
│   ├── process/
│   ├── file/
│   └── user/
├── custom/               # 自定义规则（用户维护）
│   └── *.yaml
└── disabled/             # 已禁用规则（归档）
    └── *.yaml.disabled
```

**规则模板**:
```bash
# 使用规则模板快速创建新规则
python pytbull --threat-detection create-rule \
  --template network_anomaly \
  --output conf/detection_rules/custom/my_rule.yaml
```

### 7.2 配置管理

**配置分层**:
1. 系统默认配置（`conf/threat_detection.default.cfg`）
2. 用户自定义配置（`conf/threat_detection.cfg`）
3. 环境变量覆盖

**配置验证**:
```python
# 配置文件schema验证
import jsonschema

schema = load_schema("conf/schema/threat_detection_schema.json")
config = load_config("conf/threat_detection.cfg")
jsonschema.validate(config, schema)
```

**配置热加载**:
- 监控配置文件变化
- 自动重载规则（无需重启）
- 配置变更日志记录

### 7.3 日志与调试

**日志级别**:
- DEBUG: 详细调试信息
- INFO: 一般操作信息
- WARNING: 警告信息
- ERROR: 错误信息
- CRITICAL: 严重错误

**结构化日志**:
```json
{
  "timestamp": "2026-04-29T10:30:45.123Z",
  "level": "INFO",
  "component": "RuleEngine",
  "message": "Rule matched",
  "rule_id": "NET-001",
  "event_id": "abc123",
  "context": {...}
}
```

**性能监控**:
- 事件处理延迟
- 规则匹配时间
- 队列深度
- 内存使用率
- CPU使用率

### 7.4 扩展机制

**插件架构**:
```python
# 自定义数据源插件
class CustomDataSource(DataSourcePlugin):
    def collect(self):
        # 实现数据采集逻辑
        pass

# 注册插件
register_plugin("custom_source", CustomDataSource)
```

**自定义检测器**:
```python
# 自定义检测逻辑
class CustomDetector(DetectorPlugin):
    def detect(self, event):
        # 实现检测逻辑
        if self.is_anomaly(event):
            return Alert(...)
        return None

# 在规则中使用
detector_type: "custom:my_detector"
```

**自定义告警动作**:
```python
# 自定义告警响应
class CustomAlertAction(ActionPlugin):
    def execute(self, alert):
        # 实现告警处理逻辑
        pass

# 在规则中配置
actions:
  - type: "custom:my_action"
    params: {...}
```

---

## 8. 性能评估

### 8.1 系统资源需求

**最低配置**:
- CPU: 2核
- 内存: 2GB
- 磁盘: 10GB（日志和数据库）
- 网络: 不限

**推荐配置**:
- CPU: 4核
- 内存: 4GB
- 磁盘: 50GB（SSD优先）
- 网络: 不限

### 8.2 性能指标

**处理能力**:
- 事件采集速率: >10,000 events/sec
- 规则匹配延迟: <10ms per event
- 告警生成延迟: <100ms
- 内存占用: <500MB (稳态)
- CPU占用: <10% (平均)

**扩展性**:
- 支持规则数量: >1000条
- 支持并发事件: >100,000 events in queue
- 数据库容量: >10GB (90天数据)

### 8.3 性能优化建议

1. **批量处理**: 批量匹配规则而非逐个处理
2. **索引优化**: 对常用字段建立索引
3. **缓存机制**: 缓存热点数据（GeoIP、黑名单等）
4. **异步I/O**: 使用异步写入避免阻塞
5. **数据压缩**: 压缩历史数据减少存储
6. **分区存储**: 按时间分区提高查询效率

---

## 9. 安全考虑

### 9.1 系统安全

**权限要求**:
- auditd日志读取需要root权限或auditd组成员
- 建议使用专用用户运行（如`threat-detector`）
- 配置sudo规则允许读取audit日志

**文件权限**:
```bash
# 配置文件权限
chmod 640 conf/threat_detection.cfg
chown threat-detector:threat-detector conf/threat_detection.cfg

# 日志文件权限
chmod 640 /var/log/threat_detection/*.log
chown threat-detector:threat-detector /var/log/threat_detection/

# 数据库权限
chmod 600 data/threat_detection.db
chown threat-detector:threat-detector data/threat_detection.db
```

**敏感信息保护**:
- 配置文件中的密码加密存储
- Webhook token环境变量传递
- 日志脱敏处理

### 9.2 数据安全

**数据保留**:
- 原始事件数据: 7天
- 聚合数据: 30天
- 告警数据: 90天
- 超期自动清理

**数据隔离**:
- 独立的数据库和日志目录
- 不与pytbull测试数据混合

**备份策略**:
- 配置文件每日备份
- 数据库每周备份
- 保留最近4个备份

---

## 10. 故障处理

### 10.1 常见问题

**Q1: auditd日志无法读取**
```bash
# 检查权限
ls -la /var/log/audit/audit.log

# 添加用户到auditd组
usermod -aG audit threat-detector

# 重启服务
systemctl restart threat-detection
```

**Q2: 检测规则不生效**
```bash
# 验证规则语法
python pytbull --threat-detection validate-rule conf/detection_rules/my_rule.yaml

# 查看规则加载状态
python pytbull --threat-detection list-rules

# 重载规则
python pytbull --threat-detection reload
```

**Q3: 性能下降**
```bash
# 查看系统状态
python pytbull --threat-detection status --verbose

# 查看队列深度
python pytbull --threat-detection queue-status

# 调整处理线程数
# 编辑conf/threat_detection.cfg
processing:
  workers: 8  # 增加处理线程
```

**Q4: 告警风暴**
```bash
# 启用告警抑制
alerting:
  deduplication:
    enable: true
    time_window: 300  # 5分钟内相同告警只发送一次

# 调整规则阈值
threshold:
  count: 100  # 增加阈值
  time_window: 60
```

### 10.2 调试技巧

**开启调试日志**:
```yaml
logging:
  level: DEBUG
  file: "/var/log/threat_detection/debug.log"
```

**测试单条规则**:
```bash
# 使用测试事件验证规则
python pytbull --threat-detection test-rule \
  --rule conf/detection_rules/network_anomaly.yaml \
  --event test_events/network_event.json
```

**模拟事件注入**:
```bash
# 注入测试事件
python pytbull --threat-detection inject-event \
  --type SYSCALL \
  --data '{"syscall":"connect","dest_ip":"1.1.1.1"}'
```

---

## 11. 未来扩展方向

### 11.1 机器学习增强

**行为基线**:
- 自动学习正常行为模式
- 检测统计异常偏差
- 自适应阈值调整

**异常检测算法**:
- Isolation Forest
- One-Class SVM
- LSTM时间序列预测

### 11.2 分布式部署

**架构升级**:
```
Agent (多主机) --> Message Queue (Kafka/RabbitMQ) --> Central Server --> SIEM
```

**功能**:
- 支持多主机部署
- 集中式规则管理
- 跨主机关联分析

### 11.3 威胁情报集成

**外部情报源**:
- AlienVault OTX
- MISP
- VirusTotal API
- AbuseIPDB

**功能**:
- 自动更新黑名单
- IP/域名信誉查询
- IOC匹配检测

### 11.4 响应自动化

**自动响应动作**:
- 阻断恶意IP（iptables/firewall）
- 终止恶意进程
- 隔离受感染主机
- 自动生成事件单

**SOAR集成**:
- 与安全编排平台集成
- 自动化事件响应工作流

---

## 12. 总结

### 12.1 方案优势

1. **配置驱动**: 通过YAML配置定义规则，无需编写代码，降低技术门槛
2. **模块化设计**: 清晰的分层架构，易于扩展和维护
3. **低成本**: 基于开源组件，无需商业软件授权
4. **可定制**: 灵活的规则DSL，支持复杂检测逻辑
5. **集成友好**: 支持Syslog/Webhook/CEF等标准协议，易于集成SIEM
6. **性能优良**: 异步处理，资源占用低，适合生产环境
7. **实战导向**: 基于真实威胁场景设计，覆盖常见攻击手法

### 12.2 技术可行性

**成熟技术栈**:
- Linux auditd是成熟稳定的审计框架
- Python生态丰富，有大量现成库可用
- SQLite轻量可靠，适合单机部署

**参考案例**:
- OSSEC/Wazuh: 开源HIDS，类似架构
- Falco: 云原生运行时安全，基于eBPF
- osquery: 系统查询框架，SQL式规则

**技术风险低**:
- 不依赖特殊硬件或内核补丁
- 不需要修改系统核心组件
- 向后兼容，易于升级

### 12.3 维护扩展性

**易于维护**:
- 配置文件清晰，修改方便
- 规则语法简单，学习成本低
- 完善的日志和调试工具

**易于扩展**:
- 插件式架构，支持自定义组件
- 规则模板，快速创建新规则
- 模块化代码，便于添加新功能

**长期演进**:
- 从单机版到分布式部署
- 从规则检测到机器学习
- 从被动监控到主动响应

### 12.4 实施建议

1. **分阶段实施**: 先基础框架，再高级功能
2. **小范围试点**: 先在测试环境验证，再推广生产
3. **持续优化**: 根据实际运行情况调整规则和配置
4. **知识沉淀**: 建立规则库和最佳实践文档
5. **团队培训**: 培养规则开发和系统运维能力

### 12.5 预期成果

完成后，系统将具备以下能力:

1. **实时监控**: 7x24小时监控系统活动
2. **快速检测**: 毫秒级检测异常行为
3. **准确告警**: 低误报率，高威胁覆盖
4. **可视化**: 直观的Web界面和报告
5. **易管理**: 配置式规则，低维护成本
6. **可集成**: 标准接口，融入现有安全体系

通过本方案，可以在不进行重度开发的情况下，构建一个功能完善、性能优良、易于维护的主机威胁检测系统，为Linux主机安全提供有力保障。

---

## 附录

### 附录A: 术语表

- **Auditd**: Linux审计框架，记录系统调用和事件
- **HIDS**: Host-based Intrusion Detection System，基于主机的入侵检测系统
- **SIEM**: Security Information and Event Management，安全信息与事件管理
- **IOC**: Indicator of Compromise，威胁指标
- **CEF**: Common Event Format，通用事件格式
- **DSL**: Domain Specific Language，领域特定语言
- **SOAR**: Security Orchestration, Automation and Response，安全编排自动化与响应

### 附录B: 参考文档

- Linux Audit Documentation: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing
- MITRE ATT&CK Framework: https://attack.mitre.org/
- OSSEC Documentation: https://www.ossec.net/docs/
- Falco Rules: https://falco.org/docs/rules/

### 附录C: 相关资源

**开源项目**:
- OSSEC/Wazuh: https://github.com/wazuh/wazuh
- Falco: https://github.com/falcosecurity/falco
- osquery: https://github.com/osquery/osquery

**威胁情报**:
- AlienVault OTX: https://otx.alienvault.com/
- MISP: https://www.misp-project.org/
- AbuseIPDB: https://www.abuseipdb.com/

---

**文档版本历史**:
- v1.0 (2026-04-29): 初始版本，完整设计方案
