#pragma once

#include <vector>
#include <memory>
#include <QString>
#include "InfrastructureNode.h"
#include "SpecificNodes.h"
#include "SecurityIncident.h"
#include "SpecificIncidents.h"
#include "AnalysisStrategy.h"

// Репозиторій-контейнер для управління серверною інфраструктурою та інцидентами безпеки
class InfrastructureContainer {
public:
    InfrastructureContainer();
    ~InfrastructureContainer() = default;

    // Керування вузлами інфраструктури
    void addNode(std::shared_ptr<InfrastructureNode> node);
    bool removeNode(int id);
    std::shared_ptr<InfrastructureNode> findNodeById(int id) const;
    std::shared_ptr<InfrastructureNode> findNodeByIp(const QString& ip) const;
    std::vector<std::shared_ptr<InfrastructureNode>> filterNodes(const QString& query) const;

    // Шаблонний метод фільтрації за довільним предикатом (використання знань з ЛР 2.1, 2.2)
    template <typename Predicate>
    std::vector<std::shared_ptr<InfrastructureNode>> findNodesByPredicate(Predicate pred) const {
        std::vector<std::shared_ptr<InfrastructureNode>> result;
        for (const auto& node : m_nodes) {
            if (pred(node)) {
                result.push_back(node);
            }
        }
        return result;
    }

    // Шаблонний метод агрегації числових метрик по вузлах (ЛР 2.1, 2.2)
    template <typename MetricExtractor>
    double aggregateNodeMetric(MetricExtractor extractor) const {
        if (m_nodes.empty()) return 0.0;
        double sum = 0.0;
        for (const auto& node : m_nodes) {
            sum += extractor(node);
        }
        return sum / static_cast<double>(m_nodes.size());
    }

    // Сортування вузлів (std::sort з ЛР 2.1)
    void sortNodesByMetric(bool ascending = true);
    void sortNodesByName(bool ascending = true);

    const std::vector<std::shared_ptr<InfrastructureNode>>& nodes() const { return m_nodes; }
    void clearNodes();

    // Керування інцидентами кібербезпеки
    void addIncident(std::shared_ptr<SecurityIncident> incident);
    bool resolveIncident(int id, const QString& notes);
    std::shared_ptr<SecurityIncident> findIncidentById(int id) const;
    std::vector<std::shared_ptr<SecurityIncident>> filterIncidents(const QString& query) const;

    const std::vector<std::shared_ptr<SecurityIncident>>& incidents() const { return m_incidents; }
    void clearIncidents();

    // Інтеграція зі стратегіями аудиту
    void setStrategy(std::unique_ptr<IAnalysisStrategy> strategy);
    IAnalysisStrategy* currentStrategy() const { return m_strategy.get(); }
    int runSecurityAudit();

    // Статистичні показники
    int totalNodes() const { return static_cast<int>(m_nodes.size()); }
    int onlineNodes() const;
    int criticalNodes() const;
    int activeIncidentsCount() const;
    double averageCpuUsage() const;
    double averageRamUsage() const;

    // Файлові операції введення/виведення
    void saveToFile(const QString& filePath) const;
    void loadFromFile(const QString& filePath);
    void exportIncidentReport(const QString& filePath) const;

    // Ініціалізація зразковими виробничими даними
    void loadSampleInfrastructure();

    int nextNodeId() const { return m_nextNodeId; }
    int nextIncidentId() const { return m_nextIncidentId; }

private:
    std::vector<std::shared_ptr<InfrastructureNode>> m_nodes;
    std::vector<std::shared_ptr<SecurityIncident>> m_incidents;
    std::unique_ptr<IAnalysisStrategy> m_strategy;

    int m_nextNodeId;
    int m_nextIncidentId;
};
