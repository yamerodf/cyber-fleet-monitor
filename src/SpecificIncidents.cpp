#include "SpecificIncidents.h"
#include "MonitoringExceptions.h"

// ============================================================================
// BruteForceIncident
// ============================================================================
BruteForceIncident::BruteForceIncident(int id, int targetNodeId, QString targetNodeName,
                                       QString sourceIp, IncidentSeverity severity, QString description,
                                       int failedAttempts, QString attackedService)
    : SecurityIncident(id, targetNodeId, std::move(targetNodeName), std::move(sourceIp), severity, std::move(description)),
      m_failedAttempts(failedAttempts),
      m_attackedService(std::move(attackedService)) {}

void BruteForceIncident::setFailedAttempts(int attempts) {
    if (attempts < 0) {
        throw ValidationException("Кількість спроб не може бути від'ємною.");
    }
    m_failedAttempts = attempts;
}

void BruteForceIncident::setAttackedService(const QString& service) {
    m_attackedService = service.trimmed();
}

QString BruteForceIncident::getMitigationPlan() const {
    return QString("1. Заблокувати IP-адресу %1 на рівні iptables/fail2ban.\n"
                   "2. Тимчасово обмежити доступ до служби %2 лише через VPN.\n"
                   "3. Увімкнути примусову автентифікацію за Ed25519 SSH-ключами без паролів.")
        .arg(m_sourceIp)
        .arg(m_attackedService);
}

std::shared_ptr<SecurityIncident> BruteForceIncident::clone() const {
    auto copy = std::make_shared<BruteForceIncident>(m_id, m_targetNodeId, m_targetNodeName,
                                                    m_sourceIp, m_severity, m_description,
                                                    m_failedAttempts, m_attackedService);
    copy->setTimestamp(m_timestamp);
    copy->setStatus(m_status);
    copy->setResolutionNotes(m_resolutionNotes);
    return copy;
}

QJsonObject BruteForceIncident::toJson() const {
    QJsonObject obj;
    obj["type"] = "BruteForceIncident";
    obj["id"] = m_id;
    obj["targetNodeId"] = m_targetNodeId;
    obj["targetNodeName"] = m_targetNodeName;
    obj["timestamp"] = m_timestamp.toString(Qt::ISODate);
    obj["sourceIp"] = m_sourceIp;
    obj["severity"] = static_cast<int>(m_severity);
    obj["status"] = static_cast<int>(m_status);
    obj["description"] = m_description;
    obj["resolutionNotes"] = m_resolutionNotes;
    obj["failedAttempts"] = m_failedAttempts;
    obj["attackedService"] = m_attackedService;
    return obj;
}

void BruteForceIncident::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_targetNodeId = json["targetNodeId"].toInt();
    m_targetNodeName = json["targetNodeName"].toString();
    m_timestamp = QDateTime::fromString(json["timestamp"].toString(), Qt::ISODate);
    m_sourceIp = json["sourceIp"].toString();
    m_severity = static_cast<IncidentSeverity>(json["severity"].toInt());
    m_status = static_cast<IncidentStatus>(json["status"].toInt());
    m_description = json["description"].toString();
    m_resolutionNotes = json["resolutionNotes"].toString();
    m_failedAttempts = json["failedAttempts"].toInt();
    m_attackedService = json["attackedService"].toString();
}

void BruteForceIncident::printDetails(std::ostream& os) const {
    SecurityIncident::printDetails(os);
    os << " Service:" << m_attackedService.toStdString() << " Attempts:" << m_failedAttempts;
}

// ============================================================================
// DDoSAnomalyIncident
// ============================================================================
DDoSAnomalyIncident::DDoSAnomalyIncident(int id, int targetNodeId, QString targetNodeName,
                                         QString sourceIp, IncidentSeverity severity, QString description,
                                         double trafficSpikeGbps, double packetRateKpps, QString attackVector)
    : SecurityIncident(id, targetNodeId, std::move(targetNodeName), std::move(sourceIp), severity, std::move(description)),
      m_trafficSpikeGbps(trafficSpikeGbps),
      m_packetRateKpps(packetRateKpps),
      m_attackVector(std::move(attackVector)) {}

void DDoSAnomalyIncident::setTrafficSpikeGbps(double gbps) {
    if (gbps < 0.0) {
        throw ValidationException("Сплеск трафіку не може бути від'ємним.");
    }
    m_trafficSpikeGbps = gbps;
}

void DDoSAnomalyIncident::setPacketRateKpps(double kpps) {
    if (kpps < 0.0) {
        throw ValidationException("Швидкість пакетів не може бути меншою за нуль.");
    }
    m_packetRateKpps = kpps;
}

void DDoSAnomalyIncident::setAttackVector(const QString& vector) {
    m_attackVector = vector.trimmed();
}

QString DDoSAnomalyIncident::getMitigationPlan() const {
    return QString("1. Активувати захисний профіль Cloudflare / Arbor DDoS Protection.\n"
                   "2. Увімкнути Rate Limiting для вхідних з'єднань на шлюзі (обмежити до 50 req/sec).\n"
                   "3. Застосувати BGP Anycast Blackholing для аномальних діапазонів IP.")
        .arg(m_trafficSpikeGbps);
}

std::shared_ptr<SecurityIncident> DDoSAnomalyIncident::clone() const {
    auto copy = std::make_shared<DDoSAnomalyIncident>(m_id, m_targetNodeId, m_targetNodeName,
                                                     m_sourceIp, m_severity, m_description,
                                                     m_trafficSpikeGbps, m_packetRateKpps, m_attackVector);
    copy->setTimestamp(m_timestamp);
    copy->setStatus(m_status);
    copy->setResolutionNotes(m_resolutionNotes);
    return copy;
}

QJsonObject DDoSAnomalyIncident::toJson() const {
    QJsonObject obj;
    obj["type"] = "DDoSAnomalyIncident";
    obj["id"] = m_id;
    obj["targetNodeId"] = m_targetNodeId;
    obj["targetNodeName"] = m_targetNodeName;
    obj["timestamp"] = m_timestamp.toString(Qt::ISODate);
    obj["sourceIp"] = m_sourceIp;
    obj["severity"] = static_cast<int>(m_severity);
    obj["status"] = static_cast<int>(m_status);
    obj["description"] = m_description;
    obj["resolutionNotes"] = m_resolutionNotes;
    obj["trafficSpikeGbps"] = m_trafficSpikeGbps;
    obj["packetRateKpps"] = m_packetRateKpps;
    obj["attackVector"] = m_attackVector;
    return obj;
}

void DDoSAnomalyIncident::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_targetNodeId = json["targetNodeId"].toInt();
    m_targetNodeName = json["targetNodeName"].toString();
    m_timestamp = QDateTime::fromString(json["timestamp"].toString(), Qt::ISODate);
    m_sourceIp = json["sourceIp"].toString();
    m_severity = static_cast<IncidentSeverity>(json["severity"].toInt());
    m_status = static_cast<IncidentStatus>(json["status"].toInt());
    m_description = json["description"].toString();
    m_resolutionNotes = json["resolutionNotes"].toString();
    m_trafficSpikeGbps = json["trafficSpikeGbps"].toDouble();
    m_packetRateKpps = json["packetRateKpps"].toDouble();
    m_attackVector = json["attackVector"].toString();
}

void DDoSAnomalyIncident::printDetails(std::ostream& os) const {
    SecurityIncident::printDetails(os);
    os << " Spike:" << m_trafficSpikeGbps << "Gbps Vector:" << m_attackVector.toStdString();
}

// ============================================================================
// ResourceSpikeIncident
// ============================================================================
ResourceSpikeIncident::ResourceSpikeIncident(int id, int targetNodeId, QString targetNodeName,
                                             QString sourceIp, IncidentSeverity severity, QString description,
                                             QString breachedMetric, double metricValue, QString culpritProcess)
    : SecurityIncident(id, targetNodeId, std::move(targetNodeName), std::move(sourceIp), severity, std::move(description)),
      m_breachedMetric(std::move(breachedMetric)),
      m_metricValue(metricValue),
      m_culpritProcess(std::move(culpritProcess)) {}

void ResourceSpikeIncident::setBreachedMetric(const QString& metric) {
    m_breachedMetric = metric.trimmed();
}

void ResourceSpikeIncident::setMetricValue(double val) {
    m_metricValue = val;
}

void ResourceSpikeIncident::setCulpritProcess(const QString& proc) {
    m_culpritProcess = proc.trimmed();
}

QString ResourceSpikeIncident::getMitigationPlan() const {
    return QString("1. Надіслати сигнал SIGTERM / SIGKILL аномальному процесу: %1.\n"
                   "2. Перевірити цілісність бінарних файлів за допомогою AIDE / Tripwire.\n"
                   "3. Перевірити cron-завдання та systemd unit файли на наявність автозапуску.")
        .arg(m_culpritProcess);
}

std::shared_ptr<SecurityIncident> ResourceSpikeIncident::clone() const {
    auto copy = std::make_shared<ResourceSpikeIncident>(m_id, m_targetNodeId, m_targetNodeName,
                                                       m_sourceIp, m_severity, m_description,
                                                       m_breachedMetric, m_metricValue, m_culpritProcess);
    copy->setTimestamp(m_timestamp);
    copy->setStatus(m_status);
    copy->setResolutionNotes(m_resolutionNotes);
    return copy;
}

QJsonObject ResourceSpikeIncident::toJson() const {
    QJsonObject obj;
    obj["type"] = "ResourceSpikeIncident";
    obj["id"] = m_id;
    obj["targetNodeId"] = m_targetNodeId;
    obj["targetNodeName"] = m_targetNodeName;
    obj["timestamp"] = m_timestamp.toString(Qt::ISODate);
    obj["sourceIp"] = m_sourceIp;
    obj["severity"] = static_cast<int>(m_severity);
    obj["status"] = static_cast<int>(m_status);
    obj["description"] = m_description;
    obj["resolutionNotes"] = m_resolutionNotes;
    obj["breachedMetric"] = m_breachedMetric;
    obj["metricValue"] = m_metricValue;
    obj["culpritProcess"] = m_culpritProcess;
    return obj;
}

void ResourceSpikeIncident::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_targetNodeId = json["targetNodeId"].toInt();
    m_targetNodeName = json["targetNodeName"].toString();
    m_timestamp = QDateTime::fromString(json["timestamp"].toString(), Qt::ISODate);
    m_sourceIp = json["sourceIp"].toString();
    m_severity = static_cast<IncidentSeverity>(json["severity"].toInt());
    m_status = static_cast<IncidentStatus>(json["status"].toInt());
    m_description = json["description"].toString();
    m_resolutionNotes = json["resolutionNotes"].toString();
    m_breachedMetric = json["breachedMetric"].toString();
    m_metricValue = json["metricValue"].toDouble();
    m_culpritProcess = json["culpritProcess"].toString();
}

void ResourceSpikeIncident::printDetails(std::ostream& os) const {
    SecurityIncident::printDetails(os);
    os << " Metric:" << m_breachedMetric.toStdString() << " Value:" << m_metricValue << "%";
}

// ============================================================================
// UnauthorizedAccessIncident
// ============================================================================
UnauthorizedAccessIncident::UnauthorizedAccessIncident(int id, int targetNodeId, QString targetNodeName,
                                                       QString sourceIp, IncidentSeverity severity, QString description,
                                                       QString accessedResource, int riskScore)
    : SecurityIncident(id, targetNodeId, std::move(targetNodeName), std::move(sourceIp), severity, std::move(description)),
      m_accessedResource(std::move(accessedResource)),
      m_riskScore(riskScore) {}

void UnauthorizedAccessIncident::setAccessedResource(const QString& res) {
    m_accessedResource = res.trimmed();
}

void UnauthorizedAccessIncident::setRiskScore(int score) {
    if (score < 1 || score > 100) {
        throw ValidationException("Оцінка ризику повинна бути від 1 до 100.");
    }
    m_riskScore = score;
}

QString UnauthorizedAccessIncident::getMitigationPlan() const {
    return QString("1. Негайно анулювати всі діючі JWT-токени та SSH-ключі.\n"
                   "2. Відкликати сертифікати доступу та провести інвалідні ротації паролів.\n"
                   "3. Ізолювати вузол у карантинний VLAN для форензік-аналізу логів.")
        .arg(m_accessedResource);
}

std::shared_ptr<SecurityIncident> UnauthorizedAccessIncident::clone() const {
    auto copy = std::make_shared<UnauthorizedAccessIncident>(m_id, m_targetNodeId, m_targetNodeName,
                                                            m_sourceIp, m_severity, m_description,
                                                            m_accessedResource, m_riskScore);
    copy->setTimestamp(m_timestamp);
    copy->setStatus(m_status);
    copy->setResolutionNotes(m_resolutionNotes);
    return copy;
}

QJsonObject UnauthorizedAccessIncident::toJson() const {
    QJsonObject obj;
    obj["type"] = "UnauthorizedAccessIncident";
    obj["id"] = m_id;
    obj["targetNodeId"] = m_targetNodeId;
    obj["targetNodeName"] = m_targetNodeName;
    obj["timestamp"] = m_timestamp.toString(Qt::ISODate);
    obj["sourceIp"] = m_sourceIp;
    obj["severity"] = static_cast<int>(m_severity);
    obj["status"] = static_cast<int>(m_status);
    obj["description"] = m_description;
    obj["resolutionNotes"] = m_resolutionNotes;
    obj["accessedResource"] = m_accessedResource;
    obj["riskScore"] = m_riskScore;
    return obj;
}

void UnauthorizedAccessIncident::fromJson(const QJsonObject& json) {
    m_id = json["id"].toInt();
    m_targetNodeId = json["targetNodeId"].toInt();
    m_targetNodeName = json["targetNodeName"].toString();
    m_timestamp = QDateTime::fromString(json["timestamp"].toString(), Qt::ISODate);
    m_sourceIp = json["sourceIp"].toString();
    m_severity = static_cast<IncidentSeverity>(json["severity"].toInt());
    m_status = static_cast<IncidentStatus>(json["status"].toInt());
    m_description = json["description"].toString();
    m_resolutionNotes = json["resolutionNotes"].toString();
    m_accessedResource = json["accessedResource"].toString();
    m_riskScore = json["riskScore"].toInt(90);
}

void UnauthorizedAccessIncident::printDetails(std::ostream& os) const {
    SecurityIncident::printDetails(os);
    os << " Resource:" << m_accessedResource.toStdString() << " RiskScore:" << m_riskScore;
}
