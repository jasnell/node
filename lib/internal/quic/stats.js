'use strict';

const {
  Number,
  ReflectConstruct,
  Symbol,
} = primordials;

const {
  IDX_STATS_ENDPOINT_CREATED_AT,
  IDX_STATS_ENDPOINT_DESTROYED_AT,
  IDX_STATS_ENDPOINT_BYTES_RECEIVED,
  IDX_STATS_ENDPOINT_BYTES_SENT,
  IDX_STATS_ENDPOINT_PACKETS_RECEIVED,
  IDX_STATS_ENDPOINT_PACKETS_SENT,
  IDX_STATS_ENDPOINT_SERVER_SESSIONS,
  IDX_STATS_ENDPOINT_CLIENT_SESSIONS,
  IDX_STATS_ENDPOINT_STATELESS_RESET_COUNT,
  IDX_STATS_ENDPOINT_SERVER_BUSY_COUNT,

  IDX_STATS_SESSION_CREATED_AT,
  IDX_STATS_SESSION_HANDSHAKE_COMPLETED_AT,
  IDX_STATS_SESSION_HANDSHAKE_CONFIRMED_AT,
  IDX_STATS_SESSION_SENT_AT,
  IDX_STATS_SESSION_RECEIVED_AT,
  IDX_STATS_SESSION_CLOSING_AT,
  IDX_STATS_SESSION_DESTROYED_AT,
  IDX_STATS_SESSION_BYTES_RECEIVED,
  IDX_STATS_SESSION_BYTES_SENT,
  IDX_STATS_SESSION_BIDI_STREAM_COUNT,
  IDX_STATS_SESSION_UNI_STREAM_COUNT,
  IDX_STATS_SESSION_STREAMS_IN_COUNT,
  IDX_STATS_SESSION_STREAMS_OUT_COUNT,
  IDX_STATS_SESSION_KEYUPDATE_COUNT,
  IDX_STATS_SESSION_LOSS_RETRANSMIT_COUNT,
  IDX_STATS_SESSION_MAX_BYTES_IN_FLIGHT,
  IDX_STATS_SESSION_BLOCK_COUNT,
  IDX_STATS_SESSION_BYTES_IN_FLIGHT,
  IDX_STATS_SESSION_CONGESTION_RECOVERY_START_TS,
  IDX_STATS_SESSION_CWND,
  IDX_STATS_SESSION_DELIVERY_RATE_SEC,
  IDX_STATS_SESSION_FIRST_RTT_SAMPLE_TS,
  IDX_STATS_SESSION_INITIAL_RTT,
  IDX_STATS_SESSION_LAST_TX_PKT_TS,
  IDX_STATS_SESSION_LATEST_RTT,
  IDX_STATS_SESSION_LOSS_DETECTION_TIMER,
  IDX_STATS_SESSION_LOSS_TIME,
  IDX_STATS_SESSION_MAX_UDP_PAYLOAD_SIZE,
  IDX_STATS_SESSION_MIN_RTT,
  IDX_STATS_SESSION_PTO_COUNT,
  IDX_STATS_SESSION_RTTVAR,
  IDX_STATS_SESSION_SMOOTHED_RTT,
  IDX_STATS_SESSION_SSTHRESH,
  IDX_STATS_SESSION_RECEIVE_RATE,
  IDX_STATS_SESSION_SEND_RATE,

  IDX_STATS_STREAM_CREATED_AT,
  IDX_STATS_STREAM_RECEIVED_AT,
  IDX_STATS_STREAM_ACKED_AT,
  IDX_STATS_STREAM_CLOSING_AT,
  IDX_STATS_STREAM_DESTROYED_AT,
  IDX_STATS_STREAM_BYTES_RECEIVED,
  IDX_STATS_STREAM_BYTES_SENT,
  IDX_STATS_STREAM_MAX_OFFSET,
  IDX_STATS_STREAM_MAX_OFFSET_ACK,
  IDX_STATS_STREAM_MAX_OFFSET_RECV,
  IDX_STATS_STREAM_FINAL_SIZE,
} = internalBinding('quic');

if (IDX_STATS_ENDPOINT_CREATED_AT === undefined)
  return;

const {
  customInspectSymbol: kInspect,
} = require('internal/util');

const {
  inspect,
} = require('util');

const kDetach = Symbol('kDetach');
const kDetached = Symbol('kDetached');
const kData = Symbol('kData');

class StatsBase {
  [kDetached] = false;

  /** @param {BigUint64Array} stats */
  constructor(stats) {
    this[kData] = stats;
  }

  [kDetach]() {
    if (this[kDetached]) return;
    this[kDetached] = true;
    this[kData] = this[kData].slice();
  }

  [kInspect](depth, options) {
    if (depth < 0)
      return this;

    const opts = {
      ...options,
      depth: options.depth == null ? null : options.depth - 1,
    };

    return `${this.constructor.name} ${inspect(this.toJSON(), opts)}`;
  }
}

class EndpointStats extends StatsBase {
  toJSON() {
    return {
      createdAt: Number(this.createdAt),
      duration: Number(this.duration),
      bytesReceived: Number(this.bytesReceived),
      bytesSent: Number(this.bytesSent),
      packetsReceived: Number(this.packetsReceived),
      packetsSent: Number(this.packetsSent),
      serverSessions: Number(this.serverSessions),
      clientSessions: Number(this.clientSessions),
      statelessResetCount: Number(this.statelessResetCount),
      serverBusyCount: Number(this.serverBusyCount),
    };
  }

  /** @type {bigint} */
  get createdAt() {
    return this[kData][IDX_STATS_ENDPOINT_CREATED_AT];
  }

  /** @type {bigint} */
  get duration() {
    const n = this[kData][IDX_STATS_ENDPOINT_DESTROYED_AT] ||
      process.hrtime.bigint();
    return n - this.createdAt;
  }

  /** @type {bigint} */
  get bytesReceived() {
    return this[kData][IDX_STATS_ENDPOINT_BYTES_RECEIVED];
  }

  /** @type {bigint} */
  get bytesSent() {
    return this[kData][IDX_STATS_ENDPOINT_BYTES_SENT];
  }

  /** @type {bigint} */
  get packetsReceived() {
    return this[kData][IDX_STATS_ENDPOINT_PACKETS_RECEIVED];
  }

  /** @type {bigint} */
  get packetsSent() {
    return this[kData][IDX_STATS_ENDPOINT_PACKETS_SENT];
  }

  /** @type {bigint} */
  get serverSessions() {
    return this[kData][IDX_STATS_ENDPOINT_SERVER_SESSIONS];
  }

  /** @type {bigint} */
  get clientSessions() {
    return this[kData][IDX_STATS_ENDPOINT_CLIENT_SESSIONS];
  }

  /** @type {bigint} */
  get statelessResetCount() {
    return this[kData][IDX_STATS_ENDPOINT_STATELESS_RESET_COUNT];
  }

  /** @type {bigint} */
  get serverBusyCount() {
    return this[kData][IDX_STATS_ENDPOINT_SERVER_BUSY_COUNT];
  }
}

class SessionStats extends StatsBase {
  toJSON() {
    return {
      createdAt: Number(this.createdAt),
      duration: Number(this.duration),
      handshakeCompletedAt: Number(this.handshakeCompletedAt),
      handshakeConfirmedAt: Number(this.handshakeConfirmedAt),
      lastSentAt: Number(this.lastSentAt),
      lastReceivedAt: Number(this.lastReceivedAt),
      closingAt: Number(this.closingAt),
      bytesReceived: Number(this.bytesReceived),
      bytesSent: Number(this.bytesSent),
      bidiStreamCount: Number(this.bidiStreamCount),
      uniStreamCount: Number(this.uniStreamCount),
      inboundStreamsCount: Number(this.inboundStreamsCount),
      outboundStreamsCount: Number(this.outboundStreamsCount),
      keyUpdateCount: Number(this.keyUpdateCount),
      lossRetransmitCount: Number(this.lossRetransmitCount),
      maxBytesInFlight: Number(this.maxBytesInFlight),
      blockCount: Number(this.blockCount),
      bytesInFlight: Number(this.bytesInFlight),
      congestionRecoveryStartTS: Number(this.congestionRecoveryStartTS),
      cwnd: Number(this.cwnd),
      deliveryRateSec: Number(this.deliveryRateSec),
      firstRttSampleTS: Number(this.firstRttSampleTS),
      initialRtt: Number(this.initialRtt),
      lastSentPacketTS: Number(this.lastSentPacketTS),
      latestRtt: Number(this.latestRtt),
      lossDetectionTimer: Number(this.lossDetectionTimer),
      lossTime: Number(this.lossTime),
      maxUdpPayloadSize: Number(this.maxUdpPayloadSize),
      minRtt: Number(this.minRtt),
      ptoCount: Number(this.ptoCount),
      rttVar: Number(this.rttVar),
      smoothedRtt: Number(this.smoothedRtt),
      ssthresh: Number(this.ssthresh),
      receiveRate: Number(this.receiveRate),
      sendRate: Number(this.sendRate),
    };
  }

  /** @type {bigint} */
  get createdAt() {
    return this[kData][IDX_STATS_SESSION_CREATED_AT];
  }

  /** @type {bigint} */
  get duration() {
    const n = this[kData][IDX_STATS_SESSION_DESTROYED_AT] ||
      process.hrtime.bigint();
    return n - this.createdAt;
  }

  /** @type {bigint} */
  get handshakeCompletedAt() {
    return this[kData][IDX_STATS_SESSION_HANDSHAKE_COMPLETED_AT];
  }

  /** @type {bigint} */
  get handshakeConfirmedAt() {
    return this[kData][IDX_STATS_SESSION_HANDSHAKE_CONFIRMED_AT];
  }

  /** @type {bigint} */
  get lastSentAt() {
    return this[kData][IDX_STATS_SESSION_SENT_AT];
  }

  /** @type {bigint} */
  get lastReceivedAt() {
    return this[kData][IDX_STATS_SESSION_RECEIVED_AT];
  }

  /** @type {bigint} */
  get closingAt() {
    return this[kData][IDX_STATS_SESSION_CLOSING_AT];
  }

  /** @type {bigint} */
  get bytesReceived() {
    return this[kData][IDX_STATS_SESSION_BYTES_RECEIVED];
  }

  /** @type {bigint} */
  get bytesSent() {
    return this[kData][IDX_STATS_SESSION_BYTES_SENT];
  }

  /** @type {bigint} */
  get bidiStreamCount() {
    return this[kData][IDX_STATS_SESSION_BIDI_STREAM_COUNT];
  }

  /** @type {bigint} */
  get uniStreamCount() {
    return this[kData][IDX_STATS_SESSION_UNI_STREAM_COUNT];
  }

  /** @type {bigint} */
  get inboundStreamsCount() {
    return this[kData][IDX_STATS_SESSION_STREAMS_IN_COUNT];
  }

  /** @type {bigint} */
  get outboundStreamsCount() {
    return this[kData][IDX_STATS_SESSION_STREAMS_OUT_COUNT];
  }

  /** @type {bigint} */
  get keyUpdateCount() {
    return this[kData][IDX_STATS_SESSION_KEYUPDATE_COUNT];
  }

  /** @type {bigint} */
  get lossRetransmitCount() {
    return this[kData][IDX_STATS_SESSION_LOSS_RETRANSMIT_COUNT];
  }

  /** @type {bigint} */
  get maxBytesInFlight() {
    return this[kData][IDX_STATS_SESSION_MAX_BYTES_IN_FLIGHT];
  }

  /** @type {bigint} */
  get blockCount() {
    return this[kData][IDX_STATS_SESSION_BLOCK_COUNT];
  }

  /** @type {bigint} */
  get bytesInFlight() {
    return this[kData][IDX_STATS_SESSION_BYTES_IN_FLIGHT];
  }

  /** @type {bigint} */
  get congestionRecoveryStartTS() {
    return this[kData][IDX_STATS_SESSION_CONGESTION_RECOVERY_START_TS];
  }

  /** @type {bigint} */
  get cwnd() {
    return this[kData][IDX_STATS_SESSION_CWND];
  }

  /** @type {bigint} */
  get deliveryRateSec() {
    return this[kData][IDX_STATS_SESSION_DELIVERY_RATE_SEC];
  }

  /** @type {bigint} */
  get firstRttSampleTS() {
    return this[kData][IDX_STATS_SESSION_FIRST_RTT_SAMPLE_TS];
  }

  /** @type {bigint} */
  get initialRtt() {
    return this[kData][IDX_STATS_SESSION_INITIAL_RTT];
  }

  /** @type {bigint} */
  get lastSentPacketTS() {
    return this[kData][IDX_STATS_SESSION_LAST_TX_PKT_TS];
  }

  /** @type {bigint} */
  get latestRtt() {
    return this[kData][IDX_STATS_SESSION_LATEST_RTT];
  }

  /** @type {bigint} */
  get lossDetectionTimer() {
    return this[kData][IDX_STATS_SESSION_LOSS_DETECTION_TIMER];
  }

  /** @type {bigint} */
  get lossTime() {
    return this[kData][IDX_STATS_SESSION_LOSS_TIME];
  }

  /** @type {bigint} */
  get maxUdpPayloadSize() {
    return this[kData][IDX_STATS_SESSION_MAX_UDP_PAYLOAD_SIZE];
  }

  /** @type {bigint} */
  get minRtt() {
    return this[kData][IDX_STATS_SESSION_MIN_RTT];
  }

  /** @type {bigint} */
  get ptoCount() {
    return this[kData][IDX_STATS_SESSION_PTO_COUNT];
  }

  /** @type {bigint} */
  get rttVar() {
    return this[kData][IDX_STATS_SESSION_RTTVAR];
  }

  /** @type {bigint} */
  get smoothedRtt() {
    return this[kData][IDX_STATS_SESSION_SMOOTHED_RTT];
  }

  /** @type {bigint} */
  get ssthresh() {
    return this[kData][IDX_STATS_SESSION_SSTHRESH];
  }

  /** @type {bigint} */
  get receiveRate() {
    return this[kData][IDX_STATS_SESSION_RECEIVE_RATE];
  }

  /** @type {bigint} */
  get sendRate() {
    return this[kData][IDX_STATS_SESSION_SEND_RATE];
  }
}

class StreamStats extends StatsBase {
  toJSON() {
    return {
      createdAt: Number(this.createdAt),
      duration: Number(this.duration),
      lastReceivedAt: Number(this.lastReceivedAt),
      lastAcknowledgeAt: Number(this.lastAcknowledgeAt),
      closingAt: Number(this.closingAt),
      bytesReceived: Number(this.bytesReceived),
      bytesSent: Number(this.bytesSent),
      maxOffset: Number(this.maxOffset),
      maxOffsetAcknowledged: Number(this.maxOffsetAcknowledged),
      maxOffsetReceived: Number(this.maxOffsetReceived),
      finalSize: Number(this.finalSize),
    };
  }

  /** @type {bigint} */
  get createdAt() {
    return this[kData][IDX_STATS_STREAM_CREATED_AT];
  }

  /** @type {bigint} */
  get duration() {
    const n = this[kData][IDX_STATS_STREAM_DESTROYED_AT] ||
      process.hrtime.bigint();
    return n - this.createdAt;
  }

  /** @type {bigint} */
  get lastReceivedAt() {
    return this[kData][IDX_STATS_STREAM_RECEIVED_AT];
  }

  /** @type {bigint} */
  get lastAcknowledgeAt() {
    return this[kData][IDX_STATS_STREAM_ACKED_AT];
  }

  /** @type {bigint} */
  get closingAt() {
    return this[kData][IDX_STATS_STREAM_CLOSING_AT];
  }

  /** @type {bigint} */
  get bytesReceived() {
    return this[kData][IDX_STATS_STREAM_BYTES_RECEIVED];
  }

  /** @type {bigint} */
  get bytesSent() {
    return this[kData][IDX_STATS_STREAM_BYTES_SENT];
  }

  /** @type {bigint} */
  get maxOffset() {
    return this[kData][IDX_STATS_STREAM_MAX_OFFSET];
  }

  /** @type {bigint} */
  get maxOffsetAcknowledged() {
    return this[kData][IDX_STATS_STREAM_MAX_OFFSET_ACK];
  }

  /** @type {bigint} */
  get maxOffsetReceived() {
    return this[kData][IDX_STATS_STREAM_MAX_OFFSET_RECV];
  }

  /** @type {bigint} */
  get finalSize() {
    return this[kData][IDX_STATS_STREAM_FINAL_SIZE];
  }
}

function createStats(type, data) {
  return ReflectConstruct(function(data) {
    this[kData] = data;
  }, [data], type);
}

module.exports = {
  EndpointStats,
  SessionStats,
  StreamStats,
  kDetach,
  createStats,
};
