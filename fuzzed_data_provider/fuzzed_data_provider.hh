#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>
#include <unistd.h>
#include <vector>

class FuzzedDataProviderException : public std::exception {
    const std::string msg;

public:
    FuzzedDataProviderException(const char *msg) : msg(msg) {}
    virtual const char *what() const noexcept { return msg.c_str(); }
};

class FuzzedDataBroker {
private:
    std::vector<uint8_t> *_data = nullptr;

public:
    FuzzedDataBroker() {
        size_t bufsz = 64 * 1024;
        std::vector<uint8_t> buf(bufsz);
        _data = new std::vector<uint8_t>();
        _data->reserve(bufsz);

        while (true) {
            ssize_t cnt_char = read(0, reinterpret_cast<char *>(buf.data()), bufsz);
            if (cnt_char <= 0) {
                break;
            }
            _data->insert(_data->end(), buf.begin(), buf.begin() + cnt_char);
        }
    }
    ~FuzzedDataBroker() { delete _data; }
    const uint8_t *data() const { return _data->data(); }
    const size_t size() const { return _data->size(); }
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
            throw FuzzedDataProviderException(
                std::string("Consume: out of data " +
                            std::to_string(offset + sizeof(T)) +
                            " >= " + std::to_string(size))
                    .c_str());
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
            throw FuzzedDataProviderException(
                std::string("Consume: out of data " +
                            std::to_string(offset + (length * sizeof(T))) +
                            " >= " + std::to_string(size))
                    .c_str());
        }

        T *rv = new T[length];
        memcpy(rv, data + offset, length * sizeof(T));

        return rv;
    }

    /**
     * Consume specialization for char* that null-terminates the string, because
     * there are a lot of false positives that the manpage tells you about if you
     * don't do this at least. You can twiddle and pass in something like
     * `(char*)fdp.consume<uint8>(len)` if you want to avoid the null-termination.
     *
     * @tparam T The type of the elements in the array.
     * @param length The number of elements to consume
     * @return A pointer to the array of elements
     */
    template <char> char *consume(size_t length) {
        printf("Consuming string of length %d\n", length);
        if (offset + (length * sizeof(char)) >= size && throw_on_ood) {
            throw FuzzedDataProviderException("Consume: out of data");
        }

        char *rv = new char[length];
        memcpy(rv, data + offset, (length - 1) * sizeof(char));
        rv[length - 1] = '\0';

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