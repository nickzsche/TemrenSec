# Şablon Motoru (Nuclei tarzı)

TemrenSec, YAML tespit şablonlarını çalıştıran gömülü bir motora sahiptir.
Gömülü şablonlar `pkg/templates/builtin/` altında derlenir; kendi
şablonlarını `~/.temren/templates/*.yaml` altına koyabilirsin — yeniden
derleme gerekmez, worker açılışta yükler.

## Örnek

```yaml
id: exposed-git-config
info:
  name: Exposed .git/config
  severity: high            # critical|high|medium|low|info
  description: .git/config web kökünden erişilebilir.
  owasp: "A05:2021"         # opsiyonel — rapor kategorisi
  reference: ["https://owasp.org/..."]
  remediation: .git dizinine erişimi engelleyin.
requests:
  - method: GET             # varsayılan GET
    path: ["{{BaseURL}}/.git/config"]   # {{BaseURL}} hedefe göre değişir
    headers: { }            # opsiyonel istek başlıkları
    body: ""                # opsiyonel gövde (POST için)
    matchers-condition: and # and|or (varsayılan or)
    matchers:
      - type: status        # status|word|regex|header
        status: [200]
      - type: word
        part: body          # body|header|all
        words: ["[core]", "repositoryformatversion"]
        condition: or       # çok değerli için and|or
      # - negative: true    # sonucu tersine çevir
    extractors:             # opsiyonel — eşleşen yanıttan veri çek
      - type: regex         # regex|kval
        part: body
        regex: ["version = (\\d+)"]
        group: 1            # capture grubu (0 = tüm eşleşme)
      - type: kval
        kval: ["Server", "X-Powered-By"]
```

Çıkarılan değerler bulgu kanıtına (`evidence`) eklenir. Bir şablon bir hedefte
ilk eşleşmede durur (her yol için tek bulgu). Bozuk YAML sessizce atlanır.
