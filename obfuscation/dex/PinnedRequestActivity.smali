.class public Lxyz/jserrats/certpin/PinnedRequestActivity;
.super La/b/a/j;
.source ""


# instance fields
.field public r:Landroid/widget/TextView;

.field public s:Ljava/lang/String;

.field public t:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, La/b/a/j;-><init>()V

    const-string v0, "swapi.dev"

    iput-object v0, p0, Lxyz/jserrats/certpin/PinnedRequestActivity;->s:Ljava/lang/String;

    const-string v0, "https://swapi.dev/api/people/3/"

    iput-object v0, p0, Lxyz/jserrats/certpin/PinnedRequestActivity;->t:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public n()V
    .locals 9

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 2
    iget-object v1, p0, Lxyz/jserrats/certpin/PinnedRequestActivity;->s:Ljava/lang/String;

    const-string v2, "sha256/eSiyNwaNIbIkI94wfLFmhq8/ATxm30i973pMZ669tZo="

    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x0

    if-eqz v1, :cond_5

    .line 3
    array-length v4, v2

    const/4 v5, 0x0

    move v6, v5

    :goto_0
    if-ge v6, v4, :cond_0

    aget-object v7, v2, v6

    sget-object v8, Ld/g;->b:Ld/g$b;

    invoke-virtual {v8, v1, v7}, Ld/g$b;->a(Ljava/lang/String;Ljava/lang/String;)Ld/g$c;

    move-result-object v7

    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    .line 4
    :cond_0
    new-instance v1, Ld/g;

    .line 5
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v2

    if-eqz v2, :cond_4

    const/4 v4, 0x1

    if-eq v2, v4, :cond_3

    new-instance v2, Ljava/util/LinkedHashSet;

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v6

    const/4 v7, 0x3

    if-ge v6, v7, :cond_1

    add-int/2addr v6, v4

    goto :goto_1

    :cond_1
    const/high16 v4, 0x40000000    # 2.0f

    if-ge v6, v4, :cond_2

    .line 6
    div-int/lit8 v4, v6, 0x3

    add-int/2addr v6, v4

    goto :goto_1

    :cond_2
    const v6, 0x7fffffff

    .line 7
    :goto_1
    invoke-direct {v2, v6}, Ljava/util/LinkedHashSet;-><init>(I)V

    invoke-static {v0, v2}, Lc/a/g;->a(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/Collection;

    goto :goto_2

    :cond_3
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    .line 8
    invoke-static {v0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v2

    const-string v0, "java.util.Collections.singleton(element)"

    invoke-static {v2, v0}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_2

    .line 9
    :cond_4
    sget-object v2, Lc/a/k;->a:Lc/a/k;

    .line 10
    :goto_2
    invoke-direct {v1, v2, v3}, Ld/g;-><init>(Ljava/util/Set;Ld/a/h/c;)V

    .line 11
    new-instance v0, Ld/z$a;

    invoke-direct {v0}, Ld/z$a;-><init>()V

    .line 12
    iput-object v1, v0, Ld/z$a;->u:Ld/g;

    .line 13
    new-instance v1, Ld/z;

    invoke-direct {v1, v0}, Ld/z;-><init>(Ld/z$a;)V

    .line 14
    new-instance v0, Ld/C$a;

    invoke-direct {v0}, Ld/C$a;-><init>()V

    iget-object v2, p0, Lxyz/jserrats/certpin/PinnedRequestActivity;->t:Ljava/lang/String;

    invoke-virtual {v0, v2}, Ld/C$a;->b(Ljava/lang/String;)Ld/C$a;

    invoke-virtual {v0}, Ld/C$a;->a()Ld/C;

    move-result-object v0

    .line 15
    invoke-static {v1, v0, v5}, Ld/B;->a(Ld/z;Ld/C;Z)Ld/B;

    move-result-object v0

    .line 16
    new-instance v1, Lf/a/a/c;

    invoke-direct {v1, p0}, Lf/a/a/c;-><init>(Lxyz/jserrats/certpin/PinnedRequestActivity;)V

    invoke-virtual {v0, v1}, Ld/B;->a(Ld/f;)V

    return-void

    :cond_5
    const-string v0, "pattern"

    .line 17
    invoke-static {v0}, Lc/d/b/e;->a(Ljava/lang/String;)V

    throw v3
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 0

    invoke-super {p0, p1}, La/b/a/j;->onCreate(Landroid/os/Bundle;)V

    const p1, 0x7f0b001e

    invoke-virtual {p0, p1}, La/b/a/j;->setContentView(I)V

    const p1, 0x7f08011e

    invoke-virtual {p0, p1}, La/b/a/j;->findViewById(I)Landroid/view/View;

    move-result-object p1

    check-cast p1, Landroid/widget/TextView;

    iput-object p1, p0, Lxyz/jserrats/certpin/PinnedRequestActivity;->r:Landroid/widget/TextView;

    :try_start_0
    invoke-virtual {p0}, Lxyz/jserrats/certpin/PinnedRequestActivity;->n()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-virtual {p1}, Ljava/io/IOException;->printStackTrace()V

    :goto_0
    return-void
.end method
