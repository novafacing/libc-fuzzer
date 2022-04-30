#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>

class FuzzedDataProviderException : public std::exception {
    const std::string msg;

public:
    FuzzedDataProviderException(const char *msg) : msg(msg) {}
    virtual const char *what() const noexcept {
        return ("FuzzedDataProviderException: " + msg).c_str();
    }
};

class FuzzedDataProvider {
private:
    const uint8_t *data;
    const size_t size;
    size_t offset = 0;
    const bool throw_on_ood = true;

public:
    FuzzedDataProvider(const uint8_t *data, const size_t size,
                       const bool throw_on_ood = true)
        : data(std::move(data)), size(size), throw_on_ood(throw_on_ood) {}

    /**
     * Consume a primitive value size from the data.
     *
     * @tparam T The type of the value to consume.
     * @return The consumed value.
     */
    template <typename T> T consume() {
        if (offset + sizeof(T) >= size && throw_on_ood) {
            throw FuzzedDataProviderException("Consume: out of data");
        }
        T ret = *reinterpret_cast<const T *>(data + offset);
        offset += sizeof(T);
        return ret;
    }

    /**
     * Consume bytes of the data into an array with elements of type T
     *
     * @tparam T The type of the elements in the array.
     * @param length The number of elements to consume
     * @return A pointer to the array of elements
     */
    template <typename T> T *consume(size_t length) {
        if (offset + (length * sizeof(T)) >= size && throw_on_ood) {
            throw FuzzedDataProviderException("Consume: out of data");
        }

        T *rv = new T[length];
        memcpy(rv, data + offset, length * sizeof(T));

        return rv;
    }

    /**
     * Create a pointer to some data of type T
     *
     * @tparam T The type of the data to point to.
     * @param value The value to point to
     * @return A pointer to the value
     */
    template <typename T> T *pointer(T value) {
        T *rv = new T(value);
        return rv;
    }
};