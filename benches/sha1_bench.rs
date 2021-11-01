use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hmacsha::HmacSha;
use sha1::Sha1;

pub fn criterion_benchmark(c: &mut Criterion) {
    let secret_key = "A very strong secret";
    let message = "My secret message";
    c.bench_function("SHA-1 Computation", |b| {
        b.iter(|| {
            HmacSha::from(black_box(secret_key), black_box(message), Sha1::default())
                .compute_digest()
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
