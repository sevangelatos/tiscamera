/*
 * Copyright 2013 The Imaging Source Europe GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _GST_TISCAMERASRC_H_
#define _GST_TISCAMERASRC_H_

#include <gst/gstbin.h>

G_BEGIN_DECLS

#define GST_TYPE_TISCAMERASRC   (gst_tiscamerasrc_get_type())
#define GST_TISCAMERASRC(obj)   (G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_TISCAMERASRC,GstTisCameraSrc))
#define GST_TISCAMERASRC_CLASS(klass)   (G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_TISCAMERASRC,GstTisCameraSrcClass))
#define GST_IS_TISCAMERASRC(obj)   (G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_TISCAMERASRC))
#define GST_IS_TISCAMERASRC_CLASS(obj)   (G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_TISCAMERASRC))

typedef struct _GstTisCameraSrc GstTisCameraSrc;
typedef struct _GstTisCameraSrcClass GstTisCameraSrcClass;

struct _GstTisCameraSrc
{
	GstBin base_tiscamerasrc;

	GstPad *srcpad;

	GstElement *src;
	GstElement *flt;
	GstElement *wb;
	GstElement *capsfilter;
	GstElement *capssetter;
	GstElement *debayer;
	GstElement *identity;

	gchar *device;

};

struct _GstTisCameraSrcClass
{
	GstBinClass base_tiscamerasrc_class;
};

GType gst_tiscamerasrc_get_type (void);

G_END_DECLS

#endif
