package route

// inboundOSProfile identifies the originating OS class inferred from the raw
// L3 TTL / Hop Limit and TCP SYN options of an inbound proxy flow.
type inboundOSProfile uint8

const (
	inboundOSUnknown inboundOSProfile = iota
	inboundOSLinux                    // Linux / Android (TTL<=64 + non-Apple TCP SYN, or relayed TTL 129..192)
	inboundOSWindows                  // Windows (TTL 65..128)
	inboundOSApple                    // Apple macOS/iOS (relayed TTL 193..255, direct TCP SYN [2,1,3,1,1,8], or direct UDP TTL<=64 fallback)
)
