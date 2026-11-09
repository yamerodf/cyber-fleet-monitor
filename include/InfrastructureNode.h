#pragma once

#include <QString>
#include <QJsonObject>
#include <memory>
#include <iostream>

// Статуси працездатності інфраструктурного вузла
enum class NodeStatus {
    Online,
    Warning,
    Critical,
    Offline
};

// Типи вузлів в інфраструктурі
enum class NodeType {
    GenericServer,
    DatabaseCluster,
    NetworkGateway
};

// Базовий абстрактний клас для всіх вузлів серверної інфраструктури
class InfrastructureNode {
public:
    InfrastructureNode(int id, QString name, QString ipAddress, QString location);
    virtual ~InfrastructureNode() = default;

    // Захист від зрізання об'єктів (Rule of 5)
    InfrastructureNode(const InfrastructureNode&) = delete;
    InfrastructureNode& operator=(const InfrastructureNode&) = delete;
    InfrastructureNode(InfrastructureNode&&) noexcept = default;
    InfrastructureNode& operator=(InfrastructureNode&&) noexcept = default;

    // Гетери та сетери
    int id() const { return m_id; }
    void setId(int id) { m_id = id; }

    const QString& name() const { return m_name; }
    void setName(const QString& name);

    const QString& ipAddress() const { return m_ipAddress; }
    void setIpAddress(const QString& ip);

    const QString& location() const { return m_location; }
    void setLocation(const QString& loc);

    double cpuUsage() const { return m_cpuUsage; }
    void setCpuUsage(double cpu);

    double ramUsage() const { return m_ramUsage; }
    void setRamUsage(double ram);

    int uptimeHours() const { return m_uptimeHours; }
    void setUptimeHours(int hours);

    NodeStatus status() const { return m_status; }
    void setStatus(NodeStatus status) { m_status = status; }
    QString statusString() const;

    // Чисто віртуальні методи (поліморфний інтерфейс)
    virtual NodeType type() const = 0;
    virtual QString typeName() const = 0;
    virtual QString getHealthSummary() const = 0;
    virtual double getPrimaryMetric() const = 0;
    virtual std::shared_ptr<InfrastructureNode> clone() const = 0;
    virtual QJsonObject toJson() const = 0;
    virtual void fromJson(const QJsonObject& json) = 0;

    // Оцінка стану здоров'я на основі телеметрії
    virtual void updateHealthStatus();

    // Перевантажені операції
    virtual bool operator<(const InfrastructureNode& other) const;
    virtual bool operator==(const InfrastructureNode& other) const;
    bool operator!=(const InfrastructureNode& other) const;

    friend std::ostream& operator<<(std::ostream& os, const InfrastructureNode& node);

protected:
    virtual void printDetails(std::ostream& os) const;

    int m_id;
    QString m_name;
    QString m_ipAddress;
    QString m_location;
    double m_cpuUsage;
    double m_ramUsage;
    int m_uptimeHours;
    NodeStatus m_status;
};
