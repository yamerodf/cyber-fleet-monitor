#include "SecurityIncident.h"
#include "MonitoringExceptions.h"

// Конструктор базового інциденту
SecurityIncident::SecurityIncident(int id, int targetNodeId, QString targetNodeName,
                                   QString sourceIp, IncidentSeverity severity, QString description)
    : m_id(id),
      m_targetNodeId(targetNodeId),
      m_targetNodeName(std::move(targetNodeName)),
      m_timestamp(QDateTime::currentDateTime()),
      m_sourceIp(std::move(sourceIp)),
      m_severity(severity),
      m_status(IncidentStatus::New),
      m_description(std::move(description)),
      m_resolutionNotes("") {
    if (m_targetNodeName.trimmed().isEmpty()) {
        throw ValidationException("Цільовий вузол інциденту обов'язковий.");
    }
}

void SecurityIncident::setTargetNodeName(const QString& name) {
    if (name.trimmed().isEmpty()) {
        throw ValidationException("Назва вузла не може бути порожньою.");
    }
    m_targetNodeName = name.trimmed();
}

void SecurityIncident::setSourceIp(const QString& ip) {
    m_sourceIp = ip.trimmed();
}

void SecurityIncident::setDescription(const QString& desc) {
    m_description = desc.trimmed();
}

void SecurityIncident::setResolutionNotes(const QString& notes) {
    m_resolutionNotes = notes.trimmed();
}

// Позначення інциденту як розв'язаного
void SecurityIncident::resolve(const QString& notes) {
    m_status = IncidentStatus::Resolved;
    m_resolutionNotes = notes.trimmed();
}

QString SecurityIncident::severityString() const {
    switch (m_severity) {
        case IncidentSeverity::Low:      return "Low (Низький)";
        case IncidentSeverity::Medium:   return "Medium (Середній)";
        case IncidentSeverity::High:     return "High (Високий)";
        case IncidentSeverity::Critical: return "Critical (Критичний)";
    }
    return "Unknown";
}

QString SecurityIncident::statusString() const {
    switch (m_status) {
        case IncidentStatus::New:        return "Новий (Очікує розгляду)";
        case IncidentStatus::InProgress: return "В роботі (SecOps)";
        case IncidentStatus::Mitigated:  return "Нейтралізовано (IP заблоковано)";
        case IncidentStatus::Resolved:   return "Вирішено (Закрито)";
    }
    return "Unknown";
}

// Порівняння за критичністю та часом
bool SecurityIncident::operator<(const SecurityIncident& other) const {
    if (m_severity != other.m_severity) {
        return static_cast<int>(m_severity) > static_cast<int>(other.m_severity); // вища критичність спочатку
    }
    return m_timestamp > other.m_timestamp; // новіші спочатку
}

bool SecurityIncident::operator==(const SecurityIncident& other) const {
    return (m_id == other.m_id);
}

bool SecurityIncident::operator!=(const SecurityIncident& other) const {
    return !(*this == other);
}

std::ostream& operator<<(std::ostream& os, const SecurityIncident& inc) {
    inc.printDetails(os);
    return os;
}

void SecurityIncident::printDetails(std::ostream& os) const {
    os << "[" << categoryName().toStdString() << "] ID:" << m_id
       << " Target:" << m_targetNodeName.toStdString()
       << " Severity:" << severityString().toStdString()
       << " SourceIP:" << m_sourceIp.toStdString()
       << " Status:" << statusString().toStdString();
}
