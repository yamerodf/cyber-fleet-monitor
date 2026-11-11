#pragma once

#include <vector>
#include <memory>
#include "InfrastructureNode.h"
#include "SecurityIncident.h"
#include "SpecificIncidents.h"

// Інтерфейс патерну Стратегія (Strategy Pattern) для аналізу метрик та виявлення загроз
class IAnalysisStrategy {
public:
    virtual ~IAnalysisStrategy() = default;
    virtual QString strategyName() const = 0;
    virtual std::vector<std::shared_ptr<SecurityIncident>> analyze(
        const std::vector<std::shared_ptr<InfrastructureNode>>& nodes, int& nextIncidentId) = 0;
};

// Конкретна стратегія 1: Базовий пороговий аналіз (Threshold Analysis)
class ThresholdAnalysisStrategy : public IAnalysisStrategy {
public:
    QString strategyName() const override { return "Пороговий сигнатурний аналіз (Threshold Strategy)"; }
    std::vector<std::shared_ptr<SecurityIncident>> analyze(
        const std::vector<std::shared_ptr<InfrastructureNode>>& nodes, int& nextIncidentId) override;
};

// Конкретна стратегія 2: Евристичний аналіз аномалій та сплесків (Heuristic Anomaly Strategy)
class HeuristicAnomalyStrategy : public IAnalysisStrategy {
public:
    QString strategyName() const override { return "Евристичний поведінковий моніторинг (Heuristic Strategy)"; }
    std::vector<std::shared_ptr<SecurityIncident>> analyze(
        const std::vector<std::shared_ptr<InfrastructureNode>>& nodes, int& nextIncidentId) override;
};
