#pragma once

#include "SecurityIncident.h"
#include <QStringList>

// 1. Атака типу Brute-Force (підбір облікових даних)
class BruteForceIncident : public SecurityIncident {
public:
    BruteForceIncident(int id, int targetNodeId, QString targetNodeName,
                       QString sourceIp, IncidentSeverity severity, QString description,
                       int failedAttempts = 42, QString attackedService = "SSH (порт 22)");

    QString categoryName() const override { return "Brute-Force Атака"; }
    QString getMitigationPlan() const override;

    int failedAttempts() const { return m_failedAttempts; }
    void setFailedAttempts(int attempts);

    const QString& attackedService() const { return m_attackedService; }
    void setAttackedService(const QString& service);

    std::shared_ptr<SecurityIncident> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    int m_failedAttempts;
    QString m_attackedService;
};

// 2. Аномалія мережевого трафіку / DDoS-атака
class DDoSAnomalyIncident : public SecurityIncident {
public:
    DDoSAnomalyIncident(int id, int targetNodeId, QString targetNodeName,
                        QString sourceIp, IncidentSeverity severity, QString description,
                        double trafficSpikeGbps = 8.5, double packetRateKpps = 450.0,
                        QString attackVector = "SYN Flood / UDP Amplification");

    QString categoryName() const override { return "DDoS Аномалія"; }
    QString getMitigationPlan() const override;

    double trafficSpikeGbps() const { return m_trafficSpikeGbps; }
    void setTrafficSpikeGbps(double gbps);

    double packetRateKpps() const { return m_packetRateKpps; }
    void setPacketRateKpps(double kpps);

    const QString& attackVector() const { return m_attackVector; }
    void setAttackVector(const QString& vector);

    std::shared_ptr<SecurityIncident> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    double m_trafficSpikeGbps;
    double m_packetRateKpps;
    QString m_attackVector;
};

// 3. Аномальне вичерпання ресурсів (Resource Spike / Potential Crypto-miner / Memory Leak)
class ResourceSpikeIncident : public SecurityIncident {
public:
    ResourceSpikeIncident(int id, int targetNodeId, QString targetNodeName,
                          QString sourceIp, IncidentSeverity severity, QString description,
                          QString breachedMetric = "CPU Usage", double metricValue = 98.4,
                          QString culpritProcess = "xmrig-daemon [PID 14201]");

    QString categoryName() const override { return "Вичерпання Ресурсів"; }
    QString getMitigationPlan() const override;

    const QString& breachedMetric() const { return m_breachedMetric; }
    void setBreachedMetric(const QString& metric);

    double metricValue() const { return m_metricValue; }
    void setMetricValue(double val);

    const QString& culpritProcess() const { return m_culpritProcess; }
    void setCulpritProcess(const QString& proc);

    std::shared_ptr<SecurityIncident> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    QString m_breachedMetric;
    double m_metricValue;
    QString m_culpritProcess;
};

// 4. Несанкціонований доступ до конфіденційних файлів чи облікових записів
class UnauthorizedAccessIncident : public SecurityIncident {
public:
    UnauthorizedAccessIncident(int id, int targetNodeId, QString targetNodeName,
                               QString sourceIp, IncidentSeverity severity, QString description,
                               QString accessedResource = "/etc/shadow & /var/secrets/jwt_private.pem",
                               int riskScore = 95);

    QString categoryName() const override { return "Несанкціонований Доступ"; }
    QString getMitigationPlan() const override;

    const QString& accessedResource() const { return m_accessedResource; }
    void setAccessedResource(const QString& res);

    int riskScore() const { return m_riskScore; }
    void setRiskScore(int score);

    std::shared_ptr<SecurityIncident> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    QString m_accessedResource;
    int m_riskScore;
};
