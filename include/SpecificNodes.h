#pragma once

#include "InfrastructureNode.h"

// Клас загального обчислювального сервера (Compute Server)
class ServerNode : public InfrastructureNode {
public:
    ServerNode(int id, QString name, QString ipAddress, QString location,
               QString osVersion = "Ubuntu 24.04 LTS", int activeServices = 8,
               double diskUsage = 45.0, int sshPort = 22);

    NodeType type() const override { return NodeType::GenericServer; }
    QString typeName() const override { return "Compute Server"; }

    const QString& osVersion() const { return m_osVersion; }
    void setOsVersion(const QString& os);

    int activeServices() const { return m_activeServices; }
    void setActiveServices(int count);

    double diskUsage() const { return m_diskUsage; }
    void setDiskUsage(double disk);

    int sshPort() const { return m_sshPort; }
    void setSshPort(int port);

    QString getHealthSummary() const override;
    double getPrimaryMetric() const override { return m_cpuUsage; }
    std::shared_ptr<InfrastructureNode> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

    void updateHealthStatus() override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    QString m_osVersion;
    int m_activeServices;
    double m_diskUsage;
    int m_sshPort;
};

// Клас кластера баз даних (Database Cluster)
class DatabaseNode : public InfrastructureNode {
public:
    DatabaseNode(int id, QString name, QString ipAddress, QString location,
                 QString dbEngine = "PostgreSQL 16", double qps = 850.0,
                 int activeConnections = 64, double storageGb = 250.0);

    NodeType type() const override { return NodeType::DatabaseCluster; }
    QString typeName() const override { return "Database Cluster"; }

    const QString& dbEngine() const { return m_dbEngine; }
    void setDbEngine(const QString& engine);

    double queriesPerSecond() const { return m_qps; }
    void setQueriesPerSecond(double qps);

    int activeConnections() const { return m_activeConnections; }
    void setActiveConnections(int conns);

    double storageGb() const { return m_storageGb; }
    void setStorageGb(double gb);

    QString getHealthSummary() const override;
    double getPrimaryMetric() const override { return m_qps; }
    std::shared_ptr<InfrastructureNode> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

    void updateHealthStatus() override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    QString m_dbEngine;
    double m_qps;
    int m_activeConnections;
    double m_storageGb;
};

// Клас мережевого шлюзу та фаєрволу (Network Gateway / Firewall)
class NetworkGatewayNode : public InfrastructureNode {
public:
    NetworkGatewayNode(int id, QString name, QString ipAddress, QString location,
                       double bandwidthMbps = 420.0, double packetDropRate = 0.02,
                       bool firewallActive = true, int blockedIpCount = 12);

    NodeType type() const override { return NodeType::NetworkGateway; }
    QString typeName() const override { return "Security Gateway"; }

    double bandwidthMbps() const { return m_bandwidthMbps; }
    void setBandwidthMbps(double mbps);

    double packetDropRate() const { return m_packetDropRate; }
    void setPacketDropRate(double dropRate);

    bool isFirewallActive() const { return m_firewallActive; }
    void setFirewallActive(bool active);

    int blockedIpCount() const { return m_blockedIpCount; }
    void setBlockedIpCount(int count);
    void incrementBlockedIp() { ++m_blockedIpCount; }

    QString getHealthSummary() const override;
    double getPrimaryMetric() const override { return m_bandwidthMbps; }
    std::shared_ptr<InfrastructureNode> clone() const override;
    QJsonObject toJson() const override;
    void fromJson(const QJsonObject& json) override;

    void updateHealthStatus() override;

protected:
    void printDetails(std::ostream& os) const override;

private:
    double m_bandwidthMbps;
    double m_packetDropRate;
    bool m_firewallActive;
    int m_blockedIpCount;
};
