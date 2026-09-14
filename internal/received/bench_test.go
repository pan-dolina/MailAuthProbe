package received

import "testing"

func BenchmarkParse(b *testing.B) {
	const value = "from mail.sender.example (mail.sender.example [198.51.100.7]) (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519) (No client certificate requested) by mx.receiver.example (Postfix) with ESMTPS id 4F1A2B3C4D for <bob@receiver.example>; Mon, 14 Sep 2026 10:11:12 +0200 (CEST)"
	for b.Loop() {
		Parse(value)
	}
}
