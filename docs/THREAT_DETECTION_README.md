# Linux Auditd威胁检测系统 - 设计文档

## 简介

本仓库包含基于Linux auditd的本地主机威胁检测系统的完整设计方案。该系统通过配置驱动的方式实现威胁检测，支持低代码开发，旨在提供易于维护和扩展的主机安全防护能力。

## 文档结构

### 核心设计文档

1. **[AUDITD_THREAT_DETECTION_DESIGN.md](docs/AUDITD_THREAT_DETECTION_DESIGN.md)**
   - 完整的系统设计方案（60+ 页）
   - 系统架构和组件设计
   - 配置驱动的DSL规则语法
   - 技术栈选择和实施建议
   - 性能评估和安全考虑

2. **[IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md)**
   - 12周详细实施计划
   - 分阶段交付计划（基础框架→检测引擎→告警报告→测试→部署）
   - 资源分配和人员配置
   - 风险管理和质量保证
   - 里程碑和验收标准

### 配置示例

#### 主配置文件
- **[threat_detection.cfg](conf/threat_detection/threat_detection.cfg)**
  - 系统主配置文件（INI格式）
  - 数据采集、检测、告警、存储等所有配置项
  - 包含详细的配置说明注释

#### Auditd监控规则
- **[process.rules](conf/threat_detection/audit_rules/process.rules)** - 进程监控规则
- **[network.rules](conf/threat_detection/audit_rules/network.rules)** - 网络监控规则
- **[file.rules](conf/threat_detection/audit_rules/file.rules)** - 文件监控规则
- **[user.rules](conf/threat_detection/audit_rules/user.rules)** - 用户行为监控规则

#### 检测规则（YAML格式）
- **[network_anomaly.yaml](conf/threat_detection/detection_rules/network_anomaly.yaml)**
  - 网络异常检测规则（5条）
  - 公网IP访问、内网扫描、高频连接、反向Shell、DNS隧道

- **[process_anomaly.yaml](conf/threat_detection/detection_rules/process_anomaly.yaml)**
  - 进程异常检测规则（7条）
  - 黑名单进程、高CPU/内存占用、Web服务器异常子进程、进程注入、危险命令

- **[file_anomaly.yaml](conf/threat_detection/detection_rules/file_anomaly.yaml)**
  - 文件系统异常检测规则（7条）
  - 敏感文件修改、Webshell创建、大文件外传、日志清理

- **[user_anomaly.yaml](conf/threat_detection/detection_rules/user_anomaly.yaml)**
  - 用户行为异常检测规则（10条）
  - 非工作时间登录、权限提升、账户变更、SSH密钥添加、历史清理

#### 黑白名单
- **黑名单**
  - [ips.txt](conf/threat_detection/blacklists/ips.txt) - 恶意IP地址
  - [domains.txt](conf/threat_detection/blacklists/domains.txt) - 恶意域名
  - [processes.txt](conf/threat_detection/blacklists/processes.txt) - 恶意进程
  - [files.txt](conf/threat_detection/blacklists/files.txt) - 恶意文件

- **白名单**
  - [ips.txt](conf/threat_detection/whitelists/ips.txt) - 可信IP地址
  - [processes.txt](conf/threat_detection/whitelists/processes.txt) - 可信进程
  - [users.txt](conf/threat_detection/whitelists/users.txt) - 可信用户

#### 规则模板
- **[rule_template.yaml](conf/threat_detection/templates/rule_template.yaml)**
  - 完整的规则开发模板
  - 包含所有可用字段和配置项说明
  - 提供多个示例规则

## 系统特性

### 核心能力

1. **全面监控**
   - 进程活动（创建、执行、终止）
   - 网络连接（TCP/UDP、外部访问、端口监听）
   - 文件操作（敏感文件、配置变更、可执行文件）
   - 用户行为（登录、权限提升、账户管理）

2. **智能检测**
   - 配置驱动的规则引擎
   - 阈值检测（频率、计数、时间窗口）
   - 事件关联分析
   - 黑白名单机制
   - 上下文信息丰富（GeoIP、进程树、文件哈希）

3. **灵活告警**
   - 多渠道输出（文件、Syslog、Webhook）
   - 告警聚合和去重
   - 优先级管理
   - 告警抑制策略

4. **可视化报告**
   - HTML可视化报告
   - 统计图表和趋势分析
   - 集成到pytbull Web界面

### 技术优势

1. **配置驱动**
   - 通过YAML配置定义检测规则，无需编写代码
   - 规则热加载，无需重启服务
   - 降低技术门槛，减少开发工作量

2. **模块化设计**
   - 清晰的分层架构（采集层→处理层→检测层→告警层）
   - 插件式架构，支持自定义扩展
   - 易于维护和功能扩展

3. **高性能**
   - 异步处理，批量操作
   - 内存和CPU占用低（<500MB, <10%）
   - 高吞吐量（>10K events/sec）

4. **易集成**
   - 支持Syslog/Webhook/CEF等标准协议
   - 可与SIEM系统集成
   - 兼容现有pytbull框架

## 检测场景示例

### 网络威胁检测
- ✅ 访问外部公网IP（排除更新服务）
- ✅ 内网端口扫描（高频端口探测）
- ✅ 反向Shell连接（Shell进程的网络连接）
- ✅ DNS隧道（异常DNS查询频率和长度）

### 进程威胁检测
- ✅ 黑名单进程启动（nc、msfvenom等渗透工具）
- ✅ 高资源占用进程（可能是挖矿程序）
- ✅ Web服务器异常子进程（Webshell执行）
- ✅ 进程注入行为（ptrace、内存写入）

### 文件威胁检测
- ✅ 敏感文件修改（/etc/passwd、/etc/shadow等）
- ✅ Webshell文件创建（Web目录下的可疑脚本）
- ✅ 大文件外传（数据外泄）
- ✅ 日志文件清理（反取证行为）

### 用户行为威胁
- ✅ 非工作时间登录（深夜、周末登录）
- ✅ 权限提升操作（sudo、su使用）
- ✅ 账户变更操作（useradd、usermod）
- ✅ SSH密钥添加（authorized_keys修改）

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Threat Detection System                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Web UI      │◄───┤ Report       │◄───┤ Alert        │   │
│  │ (CherryPy)  │    │ Engine       │    │ Manager      │   │
│  └─────────────┘    └──────────────┘    └──────┬───────┘   │
│                                                  │           │
│                                         ┌────────▼────────┐ │
│                                         │ Detection       │ │
│                                         │ Engine          │ │
│                                         │ - Rule Engine   │ │
│                                         │ - Correlation   │ │
│                                         └────────▲────────┘ │
│                                                  │           │
│                                         ┌────────┴────────┐ │
│                                         │ Event           │ │
│                                         │ Processing      │ │
│                                         │ - Parser        │ │
│                                         │ - Normalizer    │ │
│                                         └────────▲────────┘ │
│                                                  │           │
│  ┌──────────────────────────────────────────────┴─────────┐│
│  │              Data Collection Layer                      ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ ││
│  │  │ Auditd   │  │ Proc     │  │ Netlink              │ ││
│  │  │ Collector│  │ Monitor  │  │ Monitor              │ ││
│  │  └──────────┘  └──────────┘  └──────────────────────┘ ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │                                    │
  ┌──────┴─────────┐              ┌──────────┴──────────┐
  │ Audit Rules    │              │ Detection Rules     │
  │ (auditd.rules) │              │ (YAML Configs)      │
  └────────────────┘              └─────────────────────┘
```

## 规则DSL示例

```yaml
rule_id: "NET-001"
name: "外部公网IP访问检测"
category: "network"
severity: "medium"
enabled: true

data_sources:
  - auditd

conditions:
  event_type: "SYSCALL"
  syscall: ["connect", "sendto"]

  match:
    dest_ip:
      type: "public_ip"
      exclude_ranges:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"

enrichment:
  - type: "geoip"
    field: "dest_ip"

alert:
  enabled: true
  title: "检测到访问外部公网IP"
  message: "进程 {process} 访问外部IP {dest_ip} (位置: {geo_info.country})"
```

## 实施计划概览

| 阶段 | 周期 | 主要内容 | 关键交付物 |
|------|------|---------|-----------|
| 阶段1 | Week 1-2 | 基础框架开发 | 数据采集框架 |
| 阶段2 | Week 3-5 | 检测引擎开发 | 规则引擎+规则库 |
| 阶段3 | Week 6-7 | 告警报告系统 | 告警系统+Web界面 |
| 阶段4 | Week 8-9 | 优化与测试 | 测试报告 |
| 阶段5 | Week 10 | 文档与部署准备 | 完整文档+部署脚本 |
| 阶段6 | Week 11 | 试点部署 | 试点部署报告 |
| 阶段7 | Week 12 | 生产部署 | 验收报告 |
| 阶段8 | Week 13+ | 持续运维 | 规则更新+系统优化 |

**总计**: 12周完成开发和部署，第13周起进入持续运维

## 技术栈

- **编程语言**: Python 3.8+
- **数据采集**: auditd, psutil, pynetlink
- **数据处理**: pyyaml, jsonschema
- **数据存储**: SQLite3
- **Web框架**: CherryPy (现有)
- **报告生成**: Jinja2, Chart.js

## 性能指标

- 事件处理速率: >10,000 events/sec
- 规则匹配延迟: <10ms per event
- 内存占用: <500MB (稳态)
- CPU占用: <10% (平均)
- 支持规则数量: >1000条

## 快速开始

### 1. 安装依赖

```bash
# 安装系统依赖
apt-get install -y auditd python3 python3-pip

# 安装Python依赖
pip3 install pyyaml psutil jsonschema cherrypy jinja2
```

### 2. 配置Auditd规则

```bash
# 加载audit规则
cat conf/threat_detection/audit_rules/*.rules > /etc/audit/rules.d/threat_detection.rules
service auditd restart
```

### 3. 配置系统

```bash
# 编辑主配置文件
vi conf/threat_detection/threat_detection.cfg

# 根据需要调整检测规则
vi conf/threat_detection/detection_rules/*.yaml
```

### 4. 启动系统

```bash
# 启动威胁检测
python pytbull --threat-detection start

# 查看状态
python pytbull --threat-detection status

# 查看报告
python pytbull --threat-detection report
```

## 规则开发

### 使用模板创建新规则

```bash
# 复制模板
cp conf/threat_detection/templates/rule_template.yaml \
   conf/threat_detection/detection_rules/custom/my_rule.yaml

# 编辑规则
vi conf/threat_detection/detection_rules/custom/my_rule.yaml

# 测试规则
python pytbull --threat-detection test-rule \
   conf/threat_detection/detection_rules/custom/my_rule.yaml

# 重载规则（无需重启）
python pytbull --threat-detection reload
```

### 规则开发最佳实践

1. **从模板开始**: 使用提供的模板避免语法错误
2. **小范围测试**: 先在测试环境验证规则
3. **逐步优化**: 根据实际运行情况调整阈值
4. **添加注释**: 在规则中添加详细说明
5. **版本控制**: 将规则纳入Git管理

## 运维管理

### 日常监控

```bash
# 查看系统状态
python pytbull --threat-detection status --verbose

# 查看最近告警
tail -f /var/log/threat_detection/alerts.log

# 查看系统日志
tail -f /var/log/threat_detection/system.log
```

### 规则维护

```bash
# 列出所有规则
python pytbull --threat-detection list-rules

# 验证规则语法
python pytbull --threat-detection validate-rule <rule_file>

# 热加载规则
python pytbull --threat-detection reload
```

### 性能调优

```bash
# 调整处理线程数
[processing]
workers = 8  # 增加到8个线程

# 调整队列大小
[processing]
queue_size = 20000  # 增加队列容量

# 调整批量处理大小
[processing]
batch_size = 200  # 增加批处理大小
```

## 扩展性

### 自定义数据源

```python
class CustomDataSource(DataSourcePlugin):
    def collect(self):
        # 实现数据采集逻辑
        pass

register_plugin("custom_source", CustomDataSource)
```

### 自定义检测器

```python
class CustomDetector(DetectorPlugin):
    def detect(self, event):
        # 实现检测逻辑
        if self.is_anomaly(event):
            return Alert(...)
        return None
```

### 自定义告警动作

```python
class CustomAlertAction(ActionPlugin):
    def execute(self, alert):
        # 实现告警处理逻辑
        pass
```

## 与SIEM集成

### Syslog集成

```ini
[alerting]
output_syslog_enable = true
output_syslog_host = 10.0.1.100
output_syslog_port = 514
output_syslog_facility = local0
```

### Webhook集成

```ini
[alerting]
output_webhook_enable = true
output_webhook_url = http://siem-server/api/alerts
output_webhook_method = POST
output_webhook_auth_header = Authorization: Bearer YOUR_TOKEN
```

### CEF格式支持

系统支持生成CEF格式告警，便于与商业SIEM系统集成。

## 未来扩展

### 短期（3-6个月）
- 机器学习增强（行为基线、异常检测）
- 威胁情报集成（AlienVault OTX、MISP）
- 更多检测规则（目标200+）

### 中期（6-12个月）
- 分布式部署（Agent-Server架构）
- 自动化响应（阻断IP、终止进程）
- SOAR集成

### 长期（1-2年）
- 云原生支持（Kubernetes、容器安全）
- 商业化（SaaS版本）

## 贡献

欢迎贡献检测规则、功能增强和Bug修复。请遵循以下流程：

1. Fork仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

## 许可证

本项目继承pytbull的许可证。

## 联系方式

如有问题或建议，请创建Issue或联系项目维护者。

---

**最后更新**: 2026-04-29
**文档版本**: 1.0
**项目状态**: 设计阶段
