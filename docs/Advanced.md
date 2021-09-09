# Advanced usage

## Avoid mass force-close of channels

In order to minimize force-closes of channels (especially for larger nodes), it is possible to customize the way eclair handles certain situations, like outdated commitment and internal errors.

:warning: There is no magic: non-default strategies are a trade-off where it is assumed that the node is closely monitored. Instead of automatically reacting to some events, eclair will stop and await manual intervention. It is therefore reserved for advanced or professional node operators. Default strategies are best suited for smaller loosely administered nodes.

### Outdated commitments

The default behavior, when our peer tells us (proves to us) that our channel commitment is outdated, is to request a remote force-close of the channel (a.k.a. recovery).

It may happen that due to a misconfiguration, the node was accidentally restarted using e.g. an old backup, and the data wasn't really lost. In that case, simply fixing the configuration and restarting eclair would prevent a mass force-close of channels.

This is why an alternative behavior is to simply log an error and stop the node. However, because our peer may be lying when it tells us that our channel commitment data is outdated, there is a 10 min window after restart when this strategy applies. After that, the node reverts to the default strategy. 

The alternate strategy can be configured by setting `eclair.outdated-commitment-strategy=stop`  (see [`reference.conf`](https://github.com/ACINQ/eclair/blob/master/eclair-core/src/main/resources/reference.conf)).

### Unhandled exceptions

The default behavior, when we encounter an unhandled exception or internal error, is to locally force-close the channel.

Not only is there a delay before the channel balance gets refunded, but if the exception was due to some misconfiguration or bug in eclair that affects all channels, we risk force-closing all channels.

This is why an alternative behavior is to simply log an error and stop the node. Note that if you don't closely monitor your node, there is a risk that your peers take advantage of the downtime to try and cheat by publishing a revoked commitment. Additionally, while there is no known way of triggering an internal error in eclair from the outside, there may very well be a bug that allows just that, which could be used as a way to remotely stop the node (with the default behavior, it would "only" cause a local force-close of the channel).

The alternate strategy can be configured by setting `eclair.unhandled-exception-strategy=stop`  (see [`reference.conf`](https://github.com/ACINQ/eclair/blob/master/eclair-core/src/main/resources/reference.conf)).