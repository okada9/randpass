# Password entropy

The [entropy] $H$ of a password, defined as:

```math
H := \log_2 \left(
    \binom{l}{|E|} \cdot
    \frac{|E|!}{\prod e_i!} \cdot
    (|B| + |E|)^{l - |E|}
\right)
```

In particular, for $E = \emptyset$:

```math
H := \log_2(|B|^l) = l \cdot \log_2(|B|)
```

is a measure of its unpredictability, where:

- $l$: Password length.
- $B$: Set of base characters.
- $E$: Multiset of extra characters.
- $e$: Multiplicities of the elements in $E$, defined as $e_i := \left|
  \{ x \in E \mid x = x_i \} \right|$, where $x_i$ represents distinct
  characters in $E$.

[entropy]: https://en.wikipedia.org/wiki/Entropy_(information_theory)
