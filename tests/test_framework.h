// Minimal self-contained unit test framework (no external dependencies).
// Usage:
//   TEST(my_suite, my_case) { CHECK(1 + 1 == 2); REQUIRE(file.open()); ... }
//   int main() { return gp::test::Registry::instance().run_all(); }
#pragma once

#include <cstdio>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace gp::test {

struct Failure {
    std::string message;
};

class Registry {
   public:
    static Registry& instance() {
        static Registry reg;
        return reg;
    }

    void add(const std::string& name, std::function<void()> fn) {
        tests_.push_back({name, std::move(fn)});
    }

    int run_all() {
        int failed = 0;
        for (auto& t : tests_) {
            std::cout << "[ RUN  ] " << t.name << std::endl;
            try {
                t.fn();
                std::cout << "[ PASS ] " << t.name << std::endl;
            } catch (const Failure& f) {
                ++failed;
                std::cout << "[ FAIL ] " << t.name << ": " << f.message << std::endl;
            } catch (const std::exception& e) {
                ++failed;
                std::cout << "[ FAIL ] " << t.name << " (exception): " << e.what() << std::endl;
            }
        }
        std::cout << "\n"
                  << (tests_.size() - failed) << "/" << tests_.size() << " tests passed"
                  << std::endl;
        return failed == 0 ? 0 : 1;
    }

   private:
    struct Test {
        std::string name;
        std::function<void()> fn;
    };
    std::vector<Test> tests_;
};

struct Registrar {
    Registrar(const std::string& name, std::function<void()> fn) {
        Registry::instance().add(name, std::move(fn));
    }
};

}  // namespace gp::test

#define GP_CONCAT_INNER(a, b) a##b
#define GP_CONCAT(a, b) GP_CONCAT_INNER(a, b)

// CHECK: report failure and continue the test.
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::ostringstream oss_;                                             \
            oss_ << "CHECK failed: " #cond " @ " << __FILE__ << ":" << __LINE__; \
            throw gp::test::Failure{oss_.str()};                                 \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        if (!((a) == (b))) {                                                               \
            std::ostringstream oss_;                                                       \
            oss_ << "CHECK_EQ failed: " #a " == " #b " @ " << __FILE__ << ":" << __LINE__; \
            throw gp::test::Failure{oss_.str()};                                           \
        }                                                                                  \
    } while (0)

// REQUIRE: report failure and abort the test immediately.
#define REQUIRE(cond)                                                              \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::ostringstream oss_;                                               \
            oss_ << "REQUIRE failed: " #cond " @ " << __FILE__ << ":" << __LINE__; \
            throw gp::test::Failure{oss_.str()};                                   \
        }                                                                          \
    } while (0)

#define TEST(suite, name)                                                         \
    static void GP_CONCAT(gp_test_fn_, GP_CONCAT(suite, name))();                 \
    static ::gp::test::Registrar GP_CONCAT(gp_test_reg_, GP_CONCAT(suite, name))( \
        #suite "." #name, &GP_CONCAT(gp_test_fn_, GP_CONCAT(suite, name)));       \
    static void GP_CONCAT(gp_test_fn_, GP_CONCAT(suite, name))()
