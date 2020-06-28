.class public final Ld/g$b;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ld/g;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# direct methods
.method public synthetic constructor <init>(Lc/d/b/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/lang/String;)Ld/g$c;
    .locals 7

    const/4 v0, 0x0

    if-eqz p1, :cond_6

    if-eqz p2, :cond_5

    const/4 v1, 0x0

    const/4 v2, 0x2

    const-string v3, "*."

    invoke-static {p1, v3, v1, v2}, Lc/h/g;->b(Ljava/lang/String;Ljava/lang/String;ZI)Z

    move-result v3

    const-string v4, "http://"

    const-string v5, "(this as java.lang.String).substring(startIndex)"

    if-eqz v3, :cond_0

    sget-object v3, Ld/w;->b:Ld/w$b;

    invoke-static {v4}, Lb/a/a/a/a;->a(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v4

    invoke-virtual {p1, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v6

    invoke-static {v6, v5}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    .line 1
    :cond_0
    sget-object v3, Ld/w;->b:Ld/w$b;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-object v4, v6

    :goto_0
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ld/w$b;->b(Ljava/lang/String;)Ld/w;

    move-result-object v3

    .line 2
    iget-object v3, v3, Ld/w;->g:Ljava/lang/String;

    const-string v4, "sha1/"

    .line 3
    invoke-static {p2, v4, v1, v2}, Lc/h/g;->b(Ljava/lang/String;Ljava/lang/String;ZI)Z

    move-result v6

    if-eqz v6, :cond_2

    sget-object v1, Le/h;->b:Le/h$a;

    const/4 v2, 0x5

    invoke-virtual {p2, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p2

    invoke-static {p2, v5}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Le/h$a;->a(Ljava/lang/String;)Le/h;

    move-result-object p2

    if-eqz p2, :cond_1

    new-instance v0, Ld/g$c;

    invoke-direct {v0, p1, v3, v4, p2}, Ld/g$c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Le/h;)V

    goto :goto_1

    :cond_1
    invoke-static {}, Lc/d/b/e;->a()V

    throw v0

    :cond_2
    const-string v4, "sha256/"

    invoke-static {p2, v4, v1, v2}, Lc/h/g;->b(Ljava/lang/String;Ljava/lang/String;ZI)Z

    move-result v1

    if-eqz v1, :cond_4

    sget-object v1, Le/h;->b:Le/h$a;

    const/4 v2, 0x7

    invoke-virtual {p2, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p2

    invoke-static {p2, v5}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, p2}, Le/h$a;->a(Ljava/lang/String;)Le/h;

    move-result-object p2

    if-eqz p2, :cond_3

    new-instance v0, Ld/g$c;

    invoke-direct {v0, p1, v3, v4, p2}, Ld/g$c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Le/h;)V

    :goto_1
    return-object v0

    :cond_3
    invoke-static {}, Lc/d/b/e;->a()V

    throw v0

    :cond_4
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "pins must start with \'sha256/\' or \'sha1/\': "

    invoke-static {v0, p2}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    const-string p1, "pin"

    .line 4
    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    throw v0

    :cond_6
    const-string p1, "pattern"

    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    throw v0
.end method

.method public final a(Ljava/security/cert/X509Certificate;)Le/h;
    .locals 3

    if-eqz p1, :cond_0

    sget-object v0, Le/h;->b:Le/h$a;

    invoke-virtual {p1}, Ljava/security/cert/X509Certificate;->getPublicKey()Ljava/security/PublicKey;

    move-result-object p1

    const-string v1, "publicKey"

    invoke-static {p1, v1}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Ljava/security/PublicKey;->getEncoded()[B

    move-result-object p1

    const-string v1, "publicKey.encoded"

    invoke-static {p1, v1}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    .line 6
    array-length v2, p1

    invoke-virtual {v0, p1, v1, v2}, Le/h$a;->a([BII)Le/h;

    move-result-object p1

    const-string v0, "SHA-1"

    .line 7
    invoke-virtual {p1, v0}, Le/h;->a(Ljava/lang/String;)Le/h;

    move-result-object p1

    return-object p1

    :cond_0
    const-string p1, "$this$toSha1ByteString"

    .line 8
    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final a(Ljava/security/cert/Certificate;)Ljava/lang/String;
    .locals 1

    if-eqz p1, :cond_1

    instance-of v0, p1, Ljava/security/cert/X509Certificate;

    if-eqz v0, :cond_0

    const-string v0, "sha256/"

    invoke-static {v0}, Lb/a/a/a/a;->a(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    check-cast p1, Ljava/security/cert/X509Certificate;

    invoke-virtual {p0, p1}, Ld/g$b;->b(Ljava/security/cert/X509Certificate;)Le/h;

    move-result-object p1

    invoke-virtual {p1}, Le/h;->a()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Certificate pinning requires X509 certificates"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    const-string p1, "certificate"

    .line 5
    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final b(Ljava/security/cert/X509Certificate;)Le/h;
    .locals 3

    if-eqz p1, :cond_0

    sget-object v0, Le/h;->b:Le/h$a;

    invoke-virtual {p1}, Ljava/security/cert/X509Certificate;->getPublicKey()Ljava/security/PublicKey;

    move-result-object p1

    const-string v1, "publicKey"

    invoke-static {p1, v1}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Ljava/security/PublicKey;->getEncoded()[B

    move-result-object p1

    const-string v1, "publicKey.encoded"

    invoke-static {p1, v1}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    .line 1
    array-length v2, p1

    invoke-virtual {v0, p1, v1, v2}, Le/h$a;->a([BII)Le/h;

    move-result-object p1

    const-string v0, "SHA-256"

    .line 2
    invoke-virtual {p1, v0}, Le/h;->a(Ljava/lang/String;)Le/h;

    move-result-object p1

    return-object p1

    :cond_0
    const-string p1, "$this$toSha256ByteString"

    .line 3
    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method
