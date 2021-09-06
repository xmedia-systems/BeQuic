#include "net/tools/quic/be_quic_spdy_client_session.h"
#include "net/tools/quic/be_quic_spdy_client_stream.h"

namespace quic {

BeQuicSpdyClientSession::BeQuicSpdyClientSession(
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    QuicClientPushPromiseIndex* push_promise_index)
    : QuicSpdyClientSession(
        config,
        supported_versions,
        connection,
        server_id,
        crypto_config,
        push_promise_index) {

}

BeQuicSpdyClientSession::~BeQuicSpdyClientSession() {

}

std::unique_ptr<QuicSpdyClientStream> BeQuicSpdyClientSession::CreateClientStream() {
    std::unique_ptr<BeQuicSpdyClientStream> stream = std::make_unique<BeQuicSpdyClientStream>(
        GetNextOutgoingBidirectionalStreamId(), this, BIDIRECTIONAL);
    stream.get()->set_delegate(delegate_);

    std::shared_ptr<net::BeQuicSpdyDataDelegate> delegate = delegate_.lock();
    if (delegate != NULL) {
        delegate->on_stream_created(stream.get());
    }

    return stream;
}


bool BeQuicSpdyClientSession::ShouldKeepConnectionAlive() const {
    return QuicSpdySession::ShouldKeepConnectionAlive();
}

}  // namespace quic
