#include "InfrastructureNode.h"
#include "MonitoringExceptions.h"

// Конструктор базового інфраструктурного вузла
InfrastructureNode::InfrastructureNode(int id, QString name, QString ipAddress, QString location)
    : m_id(id),
      m_name(std::move(name)),
      m_ipAddress(std::move(ipAddress)),
      m_location(std::move(location)),
      m_cpuUsage(10.0),
      m_ramUsage(25.0),
      m_uptimeHours(24),
      m_status(NodeStatus::Online) {
    if (m_name.trimmed().isEmpty()) {
        throw ValidationException("Назва вузла не може бути порожньою.");
    }
    if (m_ipAddress.trimmed().isEmpty()) {
        throw ValidationException("IP-адреса вузла обов'язкова для заповнення.");
    }
}

// Встановлення назви з валідацією
void InfrastructureNode::setName(const QString& name) {
    if (name.trimmed().isEmpty()) {
        throw ValidationException("Назва вузла не може бути порожньою.");
    }
    m_name = name.trimmed();
}

// Встановлення IP-адреси
void InfrastructureNode::setIpAddress(const QString& ip) {
    if (ip.trimmed().isEmpty()) {
        throw ValidationException("IP-адреса не може бути порожньою.");
    }
    m_ipAddress = ip.trimmed();
}

// Встановлення локації датацентру
void InfrastructureNode::setLocation(const QString& loc) {
    m_location = loc.trimmed();
}

// Встановлення навантаження CPU
void InfrastructureNode::setCpuUsage(double cpu) {
    if (cpu < 0.0 || cpu > 100.0) {
        throw ValidationException("Навантаження CPU повинно бути в межах від 0% до 100%.");
    }
    m_cpuUsage = cpu;
    updateHealthStatus();
}

// Встановлення використання RAM
void InfrastructureNode::setRamUsage(double ram) {
    if (ram < 0.0 || ram > 100.0) {
        throw ValidationException("Використання RAM повинно бути в межах від 0% до 100%.");
    }
    m_ramUsage = ram;
    updateHealthStatus();
}

// Встановлення часу безперервної роботи
void InfrastructureNode::setUptimeHours(int hours) {
    if (hours < 0) {
        throw ValidationException("Uptime не може бути від'ємним.");
    }
    m_uptimeHours = hours;
}

// Текстове представлення статусу
QString InfrastructureNode::statusString() const {
    switch (m_status) {
        case NodeStatus::Online:   return "Online (Норма)";
        case NodeStatus::Warning:  return "Warning (Підвищене навантаження)";
        case NodeStatus::Critical: return "Critical (Критичний стан)";
        case NodeStatus::Offline:  return "Offline (Недоступний)";
    }
    return "Unknown";
}

// Базова оцінка стану працездатності
void InfrastructureNode::updateHealthStatus() {
    if (m_status == NodeStatus::Offline) {
        return;
    }
    if (m_cpuUsage >= 90.0 || m_ramUsage >= 92.0) {
        m_status = NodeStatus::Critical;
    } else if (m_cpuUsage >= 70.0 || m_ramUsage >= 75.0) {
        m_status = NodeStatus::Warning;
    } else {
        m_status = NodeStatus::Online;
    }
}

// Порівняння за навантаженням (оператор менше)
bool InfrastructureNode::operator<(const InfrastructureNode& other) const {
    return getPrimaryMetric() < other.getPrimaryMetric();
}

// Порівняння на рівність за ID та IP
bool InfrastructureNode::operator==(const InfrastructureNode& other) const {
    return (m_id == other.m_id) && (m_ipAddress == other.m_ipAddress);
}

// Порівняння на нерівність
bool InfrastructureNode::operator!=(const InfrastructureNode& other) const {
    return !(*this == other);
}

// Вивід у потік
std::ostream& operator<<(std::ostream& os, const InfrastructureNode& node) {
    node.printDetails(os);
    return os;
}

// Друк базової інформації
void InfrastructureNode::printDetails(std::ostream& os) const {
    os << "[" << typeName().toStdString() << "] ID:" << m_id
       << " Name:" << m_name.toStdString()
       << " IP:" << m_ipAddress.toStdString()
       << " CPU:" << m_cpuUsage << "% RAM:" << m_ramUsage << "%"
       << " Status:" << statusString().toStdString();
}
