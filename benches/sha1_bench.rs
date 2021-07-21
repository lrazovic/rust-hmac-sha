use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hmacsha::HmacSha1;

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut digest = [0u8; 20];
    let secret_key = "A very strong secret";
    let message = "My secret message";
    c.bench_function("HOTP Generation", |b| {
        b.iter(|| {
            HmacSha1::from(
                black_box(&secret_key),
                black_box(&message),
                black_box(&mut digest),
            )
            .digest()
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
