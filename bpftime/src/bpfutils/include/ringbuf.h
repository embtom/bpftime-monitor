#ifndef BPFUTILS_RINGBUF_H
#define BPFUTILS_RINGBUF_H

#include <bpf/libbpf.h>

#include <functional>
#include <memory>
#include <stdexcept>

namespace bpfutils {

template <typename T>
class RingBuffer {
  public:
    using EventHandler = std::function<void(const T&)>;

    RingBuffer(int map_fd, EventHandler handler) :
     callback_context_(std::make_unique<CallbackContext>(map_fd, std::move(handler)))
    {
        if (!callback_context_->rb_) {
            throw std::runtime_error("Failed to create ring buffer");
        }
    }

    ~RingBuffer() noexcept = default;

    RingBuffer(const RingBuffer&) = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

    RingBuffer(RingBuffer&&) noexcept = default;
    RingBuffer& operator=(RingBuffer&&) noexcept = default;

    int poll(int timeout_ms = -1)
    {
        return callback_context_ ? ring_buffer__poll(callback_context_->rb_, timeout_ms) : -1;
    }

    int consume()
    {
        return callback_context_ ? ring_buffer__consume(callback_context_->rb_) : -1;
    }

    int fd() const
    {
        return callback_context_ ? ring_buffer__epoll_fd(callback_context_->rb_) : -1;
    }

  private:
    struct CallbackContext {
        explicit CallbackContext(int map_fd, EventHandler handler) :
         handler_(std::move(handler)),
         rb_(ring_buffer__new(map_fd, &RingBuffer::Callback, this, nullptr))
        {
        }

        ~CallbackContext()
        {
            if (rb_ != nullptr) {
                ring_buffer__free(rb_);
            }
        }

        EventHandler handler_;
        ring_buffer* rb_ = nullptr;
    };

    static int Callback(void* ctx, void* data, size_t size)
    {
        if (size != sizeof(T)) {
            return 0;
        }

        auto* callback_context = static_cast<CallbackContext*>(ctx);
        callback_context->handler_(*static_cast<T*>(data));
        return 0;
    }

    std::unique_ptr<CallbackContext> callback_context_;
};

} // namespace bpfutils

#endif // BPFUTILS_RINGBUF_H
