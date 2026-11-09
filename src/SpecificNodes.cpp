#include "SpecificNodes.h"
#include "MonitoringExceptions.h"

// ============================================================================
// ServerNode
// ============================================================================
ServerNode::ServerNode(int id, QString name, QString ipAddress, QString location,
                       QString osVersion, int activeServices, double diskUsage, int sshPort)
    : InfrastructureNode(id, std::move(name), std::move(ipAddress), std::move(location)),
      m_osVersion(std::move(osVersion)),
      m_activeServices(activeServices),
      m_diskUsage(diskUsage),
      m_sshPort(sshPort) {
    updateHealthStatus();
}

void ServerNode::setOsVersion(const QString& os) {
    m_osVersion = os.trimmed();
}

void ServerNode::setActiveServices(int count) {
    if (count < 0) {
        throw ValidationException("Кількість активних служб не може бути від'ємною.");
    }
    m_activeServices = count;
}

void ServerNode::setDiskUsage(double disk) {
    if (disk < 0.0 || disk > 100.0) {
        throw ValidationException("Використання диска має бути в межах 0..100%.");
    }
    m_diskUsage = disk;
    updateHealthStatus();
}

void ServerNode::setSshPort(int port) {
    if (port <= 0 || port > 65535) {
        throw ValidationException("Номер порту SSH повинен бути від 1 до 65535.");
    }
    m_sshPort = port;
}

QString ServerNode::getHealthSummary() const {
    return QString("OS: %1 | Служб: %2 | Диск: %3% | SSH: %4")
        .arg(m_osVersion)
        .arg(m_activeServices)
        .arg(m_diskUsage, 0, 'f', 1)
        .arg(m_sshPort);
}

std::shared_ptr<InfrastructureNode> ServerNode::clone() const {
    auto copy = std::make_shared<ServerNode>(m_id, m_name, m_ipAddress, m_location,
                                            m_osVersion, m_activeServices, m_diskUsage, m_sshPort);
    copy->setCpuUsage(m_cpuUsage);
    copy->setRamUsage(m_ramUsage);
    copy->setUptimeHours(m_uptimeHours);
    copy->setStatus(m_status);
    return copy;
}

QJsonObject ServerNode::toJson() const {
    QJsonObject obj;
    obj["type"] = "GenericServer";
    obj["id"] = m_id;
    obj["name"] = m_name;
    obj["ipAddress"] = m_ipAddress;
    obj["location"] = m_location;
    obj["cpuUsage"] = m_cpuUsage;
    obj["ramUsage"] = m_ramUsage;
    obj["uptimeHours"] = m_uptimeHours;
    obj["status"] = static_cast<int>(m_status);
    obj["osVersion"] = m_osVersion;
    obj["activeServices"] = m_activeServices;
    obj["diskUsage"] = m_diskUsage;
    obj["sshPort"] = m_sshPort;
    return obj;
}

void ServerNode::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_name = json["name"].toString();
    m_ipAddress = json["ipAddress"].toString();
    m_location = json["location"].toString();
    m_cpuUsage = json["cpuUsage"].toDouble();
    m_ramUsage = json["ramUsage"].toDouble();
    m_uptimeHours = json["uptimeHours"].toInt();
    m_status = static_cast<NodeStatus>(json["status"].toInt());
    m_osVersion = json["osVersion"].toString();
    m_activeServices = json["activeServices"].toInt();
    m_diskUsage = json["diskUsage"].toDouble();
    m_sshPort = json["sshPort"].toInt(22);
}

void ServerNode::updateHealthStatus() {
    InfrastructureNode::updateHealthStatus();
    if (m_status == NodeStatus::Offline) return;

    if (m_diskUsage >= 95.0) {
        m_status = NodeStatus::Critical;
    } else if (m_diskUsage >= 85.0 && m_status == NodeStatus::Online) {
        m_status = NodeStatus::Warning;
    }
}

void ServerNode::printDetails(std::ostream& os) const {
    InfrastructureNode::printDetails(os);
    os << " OS:" << m_osVersion.toStdString() << " Disk:" << m_diskUsage << "%";
}

// ============================================================================
// DatabaseNode
// ============================================================================
DatabaseNode::DatabaseNode(int id, QString name, QString ipAddress, QString location,
                           QString dbEngine, double qps, int activeConnections, double storageGb)
    : InfrastructureNode(id, std::move(name), std::move(ipAddress), std::move(location)),
      m_dbEngine(std::move(dbEngine)),
      m_qps(qps),
      m_activeConnections(activeConnections),
      m_storageGb(storageGb) {
    updateHealthStatus();
}

void DatabaseNode::setDbEngine(const QString& engine) {
    m_dbEngine = engine.trimmed();
}

void DatabaseNode::setQueriesPerSecond(double qps) {
    if (qps < 0.0) {
        throw ValidationException("Показник QPS не може бути від'ємним.");
    }
    m_qps = qps;
    updateHealthStatus();
}

void DatabaseNode::setActiveConnections(int conns) {
    if (conns < 0) {
        throw ValidationException("Кількість підключень не може бути меншою за нуль.");
    }
    m_activeConnections = conns;
    updateHealthStatus();
}

void DatabaseNode::setStorageGb(double gb) {
    if (gb < 0.0) {
        throw ValidationException("Об'єм сховища БД не може бути від'ємним.");
    }
    m_storageGb = gb;
}

QString DatabaseNode::getHealthSummary() const {
    return QString("Рушій: %1 | QPS: %2 | Підключень: %3 | Сховище: %4 GB")
        .arg(m_dbEngine)
        .arg(m_qps, 0, 'f', 1)
        .arg(m_activeConnections)
        .arg(m_storageGb, 0, 'f', 1);
}

std::shared_ptr<InfrastructureNode> DatabaseNode::clone() const {
    auto copy = std::make_shared<DatabaseNode>(m_id, m_name, m_ipAddress, m_location,
                                              m_dbEngine, m_qps, m_activeConnections, m_storageGb);
    copy->setCpuUsage(m_cpuUsage);
    copy->setRamUsage(m_ramUsage);
    copy->setUptimeHours(m_uptimeHours);
    copy->setStatus(m_status);
    return copy;
}

QJsonObject DatabaseNode::toJson() const {
    QJsonObject obj;
    obj["type"] = "DatabaseCluster";
    obj["id"] = m_id;
    obj["name"] = m_name;
    obj["ipAddress"] = m_ipAddress;
    obj["location"] = m_location;
    obj["cpuUsage"] = m_cpuUsage;
    obj["ramUsage"] = m_ramUsage;
    obj["uptimeHours"] = m_uptimeHours;
    obj["status"] = static_cast<int>(m_status);
    obj["dbEngine"] = m_dbEngine;
    obj["qps"] = m_qps;
    obj["activeConnections"] = m_activeConnections;
    obj["storageGb"] = m_storageGb;
    return obj;
}

void DatabaseNode::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_name = json["name"].toString();
    m_ipAddress = json["ipAddress"].toString();
    m_location = json["location"].toString();
    m_cpuUsage = json["cpuUsage"].toDouble();
    m_ramUsage = json["ramUsage"].toDouble();
    m_uptimeHours = json["uptimeHours"].toInt();
    m_status = static_cast<NodeStatus>(json["status"].toInt());
    m_dbEngine = json["dbEngine"].toString();
    m_qps = json["qps"].toDouble();
    m_activeConnections = json["activeConnections"].toInt();
    m_storageGb = json["storageGb"].toDouble();
}

void DatabaseNode::updateHealthStatus() {
    InfrastructureNode::updateHealthStatus();
    if (m_status == NodeStatus::Offline) return;

    if (m_activeConnections > 500 || m_qps > 5000.0) {
        m_status = NodeStatus::Critical;
    } else if (m_activeConnections > 250 && m_status == NodeStatus::Online) {
        m_status = NodeStatus::Warning;
    }
}

void DatabaseNode::printDetails(std::ostream& os) const {
    InfrastructureNode::printDetails(os);
    os << " Engine:" << m_dbEngine.toStdString() << " QPS:" << m_qps;
}

// ============================================================================
// NetworkGatewayNode
// ============================================================================
NetworkGatewayNode::NetworkGatewayNode(int id, QString name, QString ipAddress, QString location,
                                       double bandwidthMbps, double packetDropRate,
                                       bool firewallActive, int blockedIpCount)
    : InfrastructureNode(id, std::move(name), std::move(ipAddress), std::move(location)),
      m_bandwidthMbps(bandwidthMbps),
      m_packetDropRate(packetDropRate),
      m_firewallActive(firewallActive),
      m_blockedIpCount(blockedIpCount) {
    updateHealthStatus();
}

void NetworkGatewayNode::setBandwidthMbps(double mbps) {
    if (mbps < 0.0) {
        throw ValidationException("Пропускна здатність не може бути меншою за нуль.");
    }
    m_bandwidthMbps = mbps;
    updateHealthStatus();
}

void NetworkGatewayNode::setPacketDropRate(double dropRate) {
    if (dropRate < 0.0 || dropRate > 100.0) {
        throw ValidationException("Втрата пакетів повинна бути в діапазоні 0..100%.");
    }
    m_packetDropRate = dropRate;
    updateHealthStatus();
}

void NetworkGatewayNode::setFirewallActive(bool active) {
    m_firewallActive = active;
    updateHealthStatus();
}

void NetworkGatewayNode::setBlockedIpCount(int count) {
    if (count < 0) {
        throw ValidationException("Кількість заблокованих IP не може бути від'ємною.");
    }
    m_blockedIpCount = count;
}

QString NetworkGatewayNode::getHealthSummary() const {
    return QString("Трафік: %1 Mbps | Втрати: %2% | Фаєрвол: %3 | Заблоковано: %4 IP")
        .arg(m_bandwidthMbps, 0, 'f', 1)
        .arg(m_packetDropRate, 0, 'f', 2)
        .arg(m_firewallActive ? "Активний (Увімкнено)" : "Вимкнено!")
        .arg(m_blockedIpCount);
}

std::shared_ptr<InfrastructureNode> NetworkGatewayNode::clone() const {
    auto copy = std::make_shared<NetworkGatewayNode>(m_id, m_name, m_ipAddress, m_location,
                                                    m_bandwidthMbps, m_packetDropRate,
                                                    m_firewallActive, m_blockedIpCount);
    copy->setCpuUsage(m_cpuUsage);
    copy->setRamUsage(m_ramUsage);
    copy->setUptimeHours(m_uptimeHours);
    copy->setStatus(m_status);
    return copy;
}

QJsonObject NetworkGatewayNode::toJson() const {
    QJsonObject obj;
    obj["type"] = "NetworkGateway";
    obj["id"] = m_id;
    obj["name"] = m_name;
    obj["ipAddress"] = m_ipAddress;
    obj["location"] = m_location;
    obj["cpuUsage"] = m_cpuUsage;
    obj["ramUsage"] = m_ramUsage;
    obj["uptimeHours"] = m_uptimeHours;
    obj["status"] = static_cast<int>(m_status);
    obj["bandwidthMbps"] = m_bandwidthMbps;
    obj["packetDropRate"] = m_packetDropRate;
    obj["firewallActive"] = m_firewallActive;
    obj["blockedIpCount"] = m_blockedIpCount;
    return obj;
}

void NetworkGatewayNode::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_name = json["name"].toString();
    m_ipAddress = json["ipAddress"].toString();
    m_location = json["location"].toString();
    m_cpuUsage = json["cpuUsage"].toDouble();
    m_ramUsage = json["ramUsage"].toDouble();
    m_uptimeHours = json["uptimeHours"].toInt();
    m_status = static_cast<NodeStatus>(json["status"].toInt());
    m_bandwidthMbps = json["bandwidthMbps"].toDouble();
    m_packetDropRate = json["packetDropRate"].toDouble();
    m_firewallActive = json["firewallActive"].toBool(true);
    m_blockedIpCount = json["blockedIpCount"].toInt(0);
}

void NetworkGatewayNode::updateHealthStatus() {
    InfrastructureNode::updateHealthStatus();
    if (m_status == NodeStatus::Offline) return;

    if (!m_firewallActive || m_packetDropRate > 5.0 || m_bandwidthMbps > 950.0) {
        m_status = NodeStatus::Critical;
    } else if (m_packetDropRate > 1.5 && m_status == NodeStatus::Online) {
        m_status = NodeStatus::Warning;
    }
}

void NetworkGatewayNode::printDetails(std::ostream& os) const {
    InfrastructureNode::printDetails(os);
    os << " Bandwidth:" << m_bandwidthMbps << "Mbps Drop:" << m_packetDropRate << "%";
}
