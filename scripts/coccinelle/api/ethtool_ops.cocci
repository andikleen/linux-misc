// Convert network drivers to use the SET_ETHTOOL_OPS macro
// This allows to compile out the ethtool code when not needed.
//
@@
struct ethtool_ops *ops;
struct net_device *dev;
@@
-	dev->ethtool_ops = ops;
+	SET_ETHTOOL_OPS(dev, ops);
