.class public final Ld/g;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ld/g$c;,
        Ld/g$a;,
        Ld/g$b;
    }
.end annotation


# static fields
.field public static final a:Ld/g;

.field public static final b:Ld/g$b;


# instance fields
.field public final c:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ld/g$c;",
            ">;"
        }
    .end annotation
.end field

.field public final d:Ld/a/h/c;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Ld/g$b;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ld/g$b;-><init>(Lc/d/b/c;)V

    sput-object v0, Ld/g;->b:Ld/g$b;

    new-instance v0, Ld/g$a;

    invoke-direct {v0}, Ld/g$a;-><init>()V

    invoke-virtual {v0}, Ld/g$a;->a()Ld/g;

    move-result-object v0

    sput-object v0, Ld/g;->a:Ld/g;

    return-void
.end method

.method public constructor <init>(Ljava/util/Set;Ld/a/h/c;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ld/g$c;",
            ">;",
            "Ld/a/h/c;",
            ")V"
        }
    .end annotation

    if-eqz p1, :cond_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld/g;->c:Ljava/util/Set;

    iput-object p2, p0, Ld/g;->d:Ld/a/h/c;

    return-void

    :cond_0
    const-string p1, "pins"

    .line 1
    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method


# virtual methods
.method public final a(Ljava/lang/String;Ljava/util/List;)V
    .locals 12
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "+",
            "Ljava/security/cert/Certificate;",
            ">;)V"
        }
    .end annotation

    const/4 v0, 0x0

    if-eqz p1, :cond_14

    if-eqz p2, :cond_13

    .line 1
    sget-object v1, Lc/a/i;->a:Lc/a/i;

    .line 2
    iget-object v2, p0, Ld/g;->c:Ljava/util/Set;

    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    const/4 v4, 0x0

    if-eqz v3, :cond_5

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ld/g$c;

    .line 3
    iget-object v5, v3, Ld/g$c;->a:Ljava/lang/String;

    const/4 v6, 0x2

    const-string v7, "*."

    invoke-static {v5, v7, v4, v6}, Lc/h/g;->b(Ljava/lang/String;Ljava/lang/String;ZI)Z

    move-result v5

    const/4 v6, 0x1

    if-eqz v5, :cond_1

    const/16 v5, 0x2e

    const/4 v7, 0x6

    invoke-static {p1, v5, v4, v4, v7}, Lc/h/g;->a(Ljava/lang/CharSequence;CIZI)I

    move-result v5

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v7

    sub-int/2addr v7, v5

    sub-int/2addr v7, v6

    iget-object v8, v3, Ld/g$c;->b:Ljava/lang/String;

    invoke-virtual {v8}, Ljava/lang/String;->length()I

    move-result v8

    if-ne v7, v8, :cond_2

    iget-object v7, v3, Ld/g$c;->b:Ljava/lang/String;

    add-int/lit8 v5, v5, 0x1

    const/4 v8, 0x4

    invoke-static {p1, v7, v5, v4, v8}, Lc/h/g;->a(Ljava/lang/String;Ljava/lang/String;IZI)Z

    move-result v5

    if-eqz v5, :cond_2

    move v4, v6

    goto :goto_1

    :cond_1
    iget-object v4, v3, Ld/g$c;->b:Ljava/lang/String;

    invoke-static {p1, v4}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    :cond_2
    :goto_1
    if-eqz v4, :cond_0

    .line 4
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_3

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 5
    :cond_3
    instance-of v4, v1, Lc/d/b/a/a;

    if-nez v4, :cond_4

    .line 6
    invoke-interface {v1, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 7
    :cond_4
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    const-string p2, " cannot be cast to "

    const-string v0, "kotlin.collections.MutableList"

    invoke-static {p1, p2, v0}, Lb/a/a/a/a;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 8
    new-instance p2, Ljava/lang/ClassCastException;

    invoke-direct {p2, p1}, Ljava/lang/ClassCastException;-><init>(Ljava/lang/String;)V

    .line 9
    const-class p1, Lc/d/b/k;

    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-static {p2, p1}, Lc/d/b/e;->a(Ljava/lang/Throwable;Ljava/lang/String;)Ljava/lang/Throwable;

    .line 10
    throw p2

    .line 11
    :cond_5
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_6

    return-void

    :cond_6
    iget-object v2, p0, Ld/g;->d:Ld/a/h/c;

    if-eqz v2, :cond_7

    invoke-virtual {v2, p2, p1}, Ld/a/h/c;->a(Ljava/util/List;Ljava/lang/String;)Ljava/util/List;

    move-result-object p2

    :cond_7
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    const-string v5, "null cannot be cast to non-null type java.security.cert.X509Certificate"

    if-eqz v3, :cond_f

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/security/cert/Certificate;

    if-eqz v3, :cond_e

    check-cast v3, Ljava/security/cert/X509Certificate;

    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v5

    move-object v6, v0

    move-object v7, v6

    :cond_9
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_8

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ld/g$c;

    .line 12
    iget-object v9, v8, Ld/g$c;->c:Ljava/lang/String;

    .line 13
    invoke-virtual {v9}, Ljava/lang/String;->hashCode()I

    move-result v10

    const v11, 0x68547ca

    if-eq v10, v11, :cond_b

    const v11, 0x7a530ee8

    if-ne v10, v11, :cond_d

    const-string v10, "sha256/"

    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_d

    if-nez v7, :cond_a

    sget-object v7, Ld/g;->b:Ld/g$b;

    invoke-virtual {v7, v3}, Ld/g$b;->b(Ljava/security/cert/X509Certificate;)Le/h;

    move-result-object v7

    .line 14
    :cond_a
    iget-object v8, v8, Ld/g$c;->d:Le/h;

    .line 15
    invoke-static {v8, v7}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_9

    return-void

    :cond_b
    const-string v10, "sha1/"

    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_d

    if-nez v6, :cond_c

    sget-object v6, Ld/g;->b:Ld/g$b;

    invoke-virtual {v6, v3}, Ld/g$b;->a(Ljava/security/cert/X509Certificate;)Le/h;

    move-result-object v6

    .line 16
    :cond_c
    iget-object v8, v8, Ld/g$c;->d:Le/h;

    .line 17
    invoke-static {v8, v6}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_9

    return-void

    :cond_d
    new-instance p1, Ljava/lang/AssertionError;

    const-string p2, "unsupported hashAlgorithm: "

    invoke-static {p2}, Lb/a/a/a/a;->a(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object p2

    .line 18
    iget-object v0, v8, Ld/g$c;->c:Ljava/lang/String;

    .line 19
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw p1

    :cond_e
    new-instance p1, Lc/d;

    invoke-direct {p1, v5}, Lc/d;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_f
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Certificate pinning failure!"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "\n  Peer certificate chain:"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v2

    :goto_2
    const-string v3, "\n    "

    if-ge v4, v2, :cond_11

    invoke-interface {p2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    if-eqz v6, :cond_10

    check-cast v6, Ljava/security/cert/X509Certificate;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget-object v3, Ld/g;->b:Ld/g$b;

    invoke-virtual {v3, v6}, Ld/g$b;->a(Ljava/security/cert/Certificate;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, ": "

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/security/cert/X509Certificate;->getSubjectDN()Ljava/security/Principal;

    move-result-object v3

    const-string v6, "x509Certificate.subjectDN"

    invoke-static {v3, v6}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v3}, Ljava/security/Principal;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v4, v4, 0x1

    goto :goto_2

    :cond_10
    new-instance p1, Lc/d;

    invoke-direct {p1, v5}, Lc/d;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_11
    const-string p2, "\n  Pinned certificates for "

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, ":"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_12

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ld/g$c;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    goto :goto_3

    :cond_12
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    const-string p2, "StringBuilder().apply(builderAction).toString()"

    invoke-static {p1, p2}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Ljavax/net/ssl/SSLPeerUnverifiedException;

    invoke-direct {p2, p1}, Ljavax/net/ssl/SSLPeerUnverifiedException;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_13
    const-string p1, "peerCertificates"

    .line 20
    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    throw v0

    :cond_14
    const-string p1, "hostname"

    invoke-static {p1}, Lc/d/b/e;->a(Ljava/lang/String;)V

    throw v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Ld/g;

    if-eqz v0, :cond_0

    check-cast p1, Ld/g;

    iget-object v0, p1, Ld/g;->c:Ljava/util/Set;

    iget-object v1, p0, Ld/g;->c:Ljava/util/Set;

    invoke-static {v0, v1}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p1, p1, Ld/g;->d:Ld/a/h/c;

    iget-object v0, p0, Ld/g;->d:Ld/a/h/c;

    invoke-static {p1, v0}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    return p1
.end method

.method public hashCode()I
    .locals 2

    iget-object v0, p0, Ld/g;->c:Ljava/util/Set;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/lit16 v0, v0, 0x5ed

    mul-int/lit8 v0, v0, 0x29

    iget-object v1, p0, Ld/g;->d:Ld/a/h/c;

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    add-int/2addr v0, v1

    return v0
.end method
