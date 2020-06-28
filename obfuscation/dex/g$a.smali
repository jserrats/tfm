.class public final Ld/g$a;
.super Ljava/lang/Object;
.source ""


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ld/g;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field public final a:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ld/g$c;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Ld/g$a;->a:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final a()Ld/g;
    .locals 7

    new-instance v0, Ld/g;

    iget-object v1, p0, Ld/g$a;->a:Ljava/util/List;

    const/4 v2, 0x0

    if-eqz v1, :cond_4

    const/4 v3, 0x1

    .line 1
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    if-eqz v4, :cond_3

    if-eq v4, v3, :cond_2

    new-instance v4, Ljava/util/LinkedHashSet;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v5

    const/4 v6, 0x3

    if-ge v5, v6, :cond_0

    add-int/2addr v5, v3

    goto :goto_0

    :cond_0
    const/high16 v3, 0x40000000    # 2.0f

    if-ge v5, v3, :cond_1

    .line 2
    div-int/lit8 v3, v5, 0x3

    add-int/2addr v5, v3

    goto :goto_0

    :cond_1
    const v5, 0x7fffffff

    .line 3
    :goto_0
    invoke-direct {v4, v5}, Ljava/util/LinkedHashSet;-><init>(I)V

    invoke-static {v1, v4}, Lc/a/g;->a(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/Collection;

    goto :goto_1

    :cond_2
    const/4 v3, 0x0

    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    .line 4
    invoke-static {v1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v4

    const-string v1, "java.util.Collections.singleton(element)"

    invoke-static {v4, v1}, Lc/d/b/e;->a(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_1

    .line 5
    :cond_3
    sget-object v4, Lc/a/k;->a:Lc/a/k;

    .line 6
    :goto_1
    invoke-direct {v0, v4, v2}, Ld/g;-><init>(Ljava/util/Set;Ld/a/h/c;)V

    return-object v0

    :cond_4
    const-string v0, "$this$toSet"

    .line 7
    invoke-static {v0}, Lc/d/b/e;->a(Ljava/lang/String;)V

    throw v2
.end method
