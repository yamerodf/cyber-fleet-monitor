#pragma once

#include <stdexcept>
#include <string>

// Базовий виняток системи моніторингу
class MonitoringException : public std::runtime_error {
public:
    explicit MonitoringException(const std::string& message)
        : std::runtime_error(message) {}
};

// Помилка валідації параметрів інфраструктурного вузла чи інциденту
class ValidationException : public MonitoringException {
public:
    explicit ValidationException(const std::string& message)
        : MonitoringException("Помилка валідації: " + message) {}
};

// Вузол інфраструктури не знайдено за вказаним ідентифікатором
class NodeNotFoundException : public MonitoringException {
public:
    explicit NodeNotFoundException(const std::string& message)
        : MonitoringException("Вузол інфраструктури не знайдено: " + message) {}
};

// Інцидент безпеки не знайдено в журналі
class IncidentNotFoundException : public MonitoringException {
public:
    explicit IncidentNotFoundException(const std::string& message)
        : MonitoringException("Інцидент безпеки не знайдено: " + message) {}
};

// Спроба додати вузол з дублюючою IP-адресою чи назвою
class DuplicateNodeException : public MonitoringException {
public:
    explicit DuplicateNodeException(const std::string& message)
        : MonitoringException("Дублювання інфраструктурного вузла: " + message) {}
};

// Помилка введення/виведення файлового сховища
class StorageIOException : public MonitoringException {
public:
    explicit StorageIOException(const std::string& message)
        : MonitoringException("Помилка файлового сховища: " + message) {}
};
