/*
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hdmi.h"

static struct platform_device *hdmi_pdev;

void hdmi_set_mode(struct hdmi *hdmi, bool power_on)
{
	uint32_t ctrl = 0;

	if (power_on) {
		ctrl |= HDMI_CTRL_ENABLE;
		if (!hdmi->hdmi_mode) {
			ctrl |= HDMI_CTRL_HDMI;
			hdmi_write(hdmi, REG_HDMI_CTRL, ctrl);
			ctrl &= ~HDMI_CTRL_HDMI;
		} else {
			ctrl |= HDMI_CTRL_HDMI;
		}
	} else {
		ctrl = HDMI_CTRL_HDMI;
	}

	hdmi_write(hdmi, REG_HDMI_CTRL, ctrl);
	DBG("HDMI Core: %s, HDMI_CTRL=0x%08x",
			power_on ? "Enable" : "Disable", ctrl);
}

static irqreturn_t hdmi_irq(int irq, void *dev_id)
{
	struct hdmi *hdmi = dev_id;

	/* Process HPD: */
	hdmi_connector_irq(hdmi->connector);

	/* Process DDC: */
	hdmi_i2c_irq(hdmi->i2c);

	/* TODO audio.. */

	return IRQ_HANDLED;
}

void hdmi_destroy(struct kref *kref)
{
	struct hdmi *hdmi = container_of(kref, struct hdmi, refcount);
	struct hdmi_phy *phy = hdmi->phy;

	if (phy)
		phy->funcs->destroy(phy);

	if (hdmi->i2c)
		hdmi_i2c_destroy(hdmi->i2c);

	put_device(&hdmi->pdev->dev);
}

/* initialize connector */
int hdmi_init(struct drm_device *dev, struct drm_encoder *encoder)
{
	struct hdmi *hdmi = NULL;
	struct msm_drm_private *priv = dev->dev_private;
	struct platform_device *pdev = hdmi_pdev;
	struct hdmi_platform_config *config;
	int ret;

	if (!pdev) {
		dev_err(dev->dev, "no hdmi device\n");
		ret = -ENXIO;
		goto fail;
	}

	config = pdev->dev.platform_data;

	hdmi = kzalloc(sizeof(*hdmi), GFP_KERNEL);
	if (!hdmi) {
		ret = -ENOMEM;
		goto fail;
	}

	kref_init(&hdmi->refcount);

	get_device(&pdev->dev);

	hdmi->dev = dev;
	hdmi->pdev = pdev;
	hdmi->encoder = encoder;

	/* not sure about which phy maps to which msm.. probably I miss some */
	if (config->phy_init)
		hdmi->phy = config->phy_init(hdmi);
	else
		hdmi->phy = ERR_PTR(-ENXIO);

	if (IS_ERR(hdmi->phy)) {
		ret = PTR_ERR(hdmi->phy);
		dev_err(dev->dev, "failed to load phy: %d\n", ret);
		hdmi->phy = NULL;
		goto fail;
	}

	hdmi->mmio = msm_ioremap(pdev, "hdmi_msm_hdmi_addr", "HDMI");
	if (IS_ERR(hdmi->mmio)) {
		ret = PTR_ERR(hdmi->mmio);
		goto fail;
	}

	hdmi->mvs = devm_regulator_get(&pdev->dev, "8901_hdmi_mvs");
	if (IS_ERR(hdmi->mvs))
		hdmi->mvs = devm_regulator_get(&pdev->dev, "hdmi_mvs");
	if (IS_ERR(hdmi->mvs)) {
		ret = PTR_ERR(hdmi->mvs);
		dev_err(dev->dev, "failed to get mvs regulator: %d\n", ret);
		goto fail;
	}

	hdmi->mpp0 = devm_regulator_get(&pdev->dev, "8901_mpp0");
	if (IS_ERR(hdmi->mpp0))
		hdmi->mpp0 = NULL;

	hdmi->clk = devm_clk_get(&pdev->dev, "core_clk");
	if (IS_ERR(hdmi->clk)) {
		ret = PTR_ERR(hdmi->clk);
		dev_err(dev->dev, "failed to get 'clk': %d\n", ret);
		goto fail;
	}

	hdmi->m_pclk = devm_clk_get(&pdev->dev, "master_iface_clk");
	if (IS_ERR(hdmi->m_pclk)) {
		ret = PTR_ERR(hdmi->m_pclk);
		dev_err(dev->dev, "failed to get 'm_pclk': %d\n", ret);
		goto fail;
	}

	hdmi->s_pclk = devm_clk_get(&pdev->dev, "slave_iface_clk");
	if (IS_ERR(hdmi->s_pclk)) {
		ret = PTR_ERR(hdmi->s_pclk);
		dev_err(dev->dev, "failed to get 's_pclk': %d\n", ret);
		goto fail;
	}

	hdmi->i2c = hdmi_i2c_init(hdmi);
	if (IS_ERR(hdmi->i2c)) {
		ret = PTR_ERR(hdmi->i2c);
		dev_err(dev->dev, "failed to get i2c: %d\n", ret);
		hdmi->i2c = NULL;
		goto fail;
	}

	hdmi->bridge = hdmi_bridge_init(hdmi);
	if (IS_ERR(hdmi->bridge)) {
		ret = PTR_ERR(hdmi->bridge);
		dev_err(dev->dev, "failed to create HDMI bridge: %d\n", ret);
		hdmi->bridge = NULL;
		goto fail;
	}

	hdmi->connector = hdmi_connector_init(hdmi);
	if (IS_ERR(hdmi->connector)) {
		ret = PTR_ERR(hdmi->connector);
		dev_err(dev->dev, "failed to create HDMI connector: %d\n", ret);
		hdmi->connector = NULL;
		goto fail;
	}

	hdmi->irq = platform_get_irq(pdev, 0);
	if (hdmi->irq < 0) {
		ret = hdmi->irq;
		dev_err(dev->dev, "failed to get irq: %d\n", ret);
		goto fail;
	}

	ret = devm_request_threaded_irq(&pdev->dev, hdmi->irq,
			NULL, hdmi_irq, IRQF_TRIGGER_HIGH | IRQF_ONESHOT,
			"hdmi_isr", hdmi);
	if (ret < 0) {
		dev_err(dev->dev, "failed to request IRQ%u: %d\n",
				hdmi->irq, ret);
		goto fail;
	}

	encoder->bridge = hdmi->bridge;

	priv->bridges[priv->num_bridges++]       = hdmi->bridge;
	priv->connectors[priv->num_connectors++] = hdmi->connector;

	return 0;

fail:
	if (hdmi) {
		/* bridge/connector are normally destroyed by drm: */
		if (hdmi->bridge)
			hdmi->bridge->funcs->destroy(hdmi->bridge);
		if (hdmi->connector)
			hdmi->connector->funcs->destroy(hdmi->connector);
		hdmi_destroy(&hdmi->refcount);
	}

	return ret;
}

/*
 * The hdmi device:
 */

static int hdmi_dev_probe(struct platform_device *pdev)
{
	static struct hdmi_platform_config config = {};
#ifdef CONFIG_OF
	/* TODO */
#else
	if (cpu_is_apq8064()) {
		config.phy_init      = hdmi_phy_8960_init;
		config.ddc_clk_gpio  = 70;
		config.ddc_data_gpio = 71;
		config.hpd_gpio      = 72;
		config.pmic_gpio     = 13 + NR_GPIO_IRQS;
	} else if (cpu_is_msm8960()) {
		config.phy_init      = hdmi_phy_8960_init;
		config.ddc_clk_gpio  = 100;
		config.ddc_data_gpio = 101;
		config.hpd_gpio      = 102;
		config.pmic_gpio     = -1;
	} else if (cpu_is_msm8x60()) {
		config.phy_init      = hdmi_phy_8x60_init;
		config.ddc_clk_gpio  = 170;
		config.ddc_data_gpio = 171;
		config.hpd_gpio      = 172;
		config.pmic_gpio     = -1;
	}
#endif
	pdev->dev.platform_data = &config;
	hdmi_pdev = pdev;
	return 0;
}

static int hdmi_dev_remove(struct platform_device *pdev)
{
	hdmi_pdev = NULL;
	return 0;
}

static struct platform_driver hdmi_driver = {
	.probe = hdmi_dev_probe,
	.remove = hdmi_dev_remove,
	.driver.name = "hdmi_msm",
};

void __init hdmi_register(void)
{
	platform_driver_register(&hdmi_driver);
}

void __exit hdmi_unregister(void)
{
	platform_driver_unregister(&hdmi_driver);
}
