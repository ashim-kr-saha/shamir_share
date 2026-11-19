#![no_main]

use libfuzzer_sys::fuzz_target;
use shamir_share::hsss::Hsss;

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    let threshold = ((data[0] % 8) + 2) as u8;
    let num_levels = ((data[1] % 4) + 1) as usize;
    let mut builder = Hsss::builder(threshold);

    let mut offset = 2;
    for l in 0..num_levels {
        if offset >= data.len() {
            return;
        }
        let shares = ((data[offset] % 8) + 1) as u8;
        offset += 1;
        let name = format!("Level_{l}");
        builder = builder.add_level(&name, shares);
    }

    let Ok(mut hsss) = builder.build() else {
        return;
    };

    if offset >= data.len() {
        return;
    }

    let secret_len = ((data[offset] as usize) % 256).max(1);
    offset += 1;

    let end = (offset + secret_len).min(data.len());
    let secret = &data[offset..end];
    if secret.is_empty() {
        return;
    }

    if let Ok(all_h_shares) = hsss.split_secret(secret) {
        // Reconstruct from full set
        let _ = hsss.reconstruct(&all_h_shares);

        // Reconstruct from single level
        if !all_h_shares.is_empty() {
            let _ = hsss.reconstruct(&all_h_shares[0..1]);
        }
    }
});
