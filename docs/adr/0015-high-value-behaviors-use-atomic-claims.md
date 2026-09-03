# 高价值行为使用原子Behavior Claim

每个高价值Behavior Claim只表达一个可验证行为，并结构化记录Subject、Action、Object、Mechanism、Condition、Evidence引用、Evidence Nature和Status。持久化、注入、通信、窃密等不同动作不得打包成一个宽泛能力标签，复杂能力和攻击链由多个原子Claim及Relation组合。

## Consequences

ATT&CK映射绑定Behavior Claim而不是整个Artifact或报告；代码实现某行为与运行时实际发生该行为使用不同Claim。报告模块可以聚合多个Claim形成叙述，但不得在聚合时引入新的未验证事实。
