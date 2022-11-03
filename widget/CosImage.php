<?php

namespace beacon\widget;

use beacon\core\Config;
use beacon\core\Field;

#[\Attribute]
class CosImage extends Field
{
    public string $mode = 'image';
    public string $extensions = 'jpg,jpeg,bmp,gif,png';
    public int $imgWidth = 0;
    public int $imgHeight = 0;
    public int $size = 0;
    public string $folder;

    public function setting(array $args): void
    {
        parent::setting($args);
        if (isset($args['mode']) && is_string($args['mode'])) {
            $this->mode = $args['mode'];
        }
        if (isset($args['extensions']) && is_string($args['extensions'])) {
            $this->extensions = $args['extensions'];
        }
        if (isset($args['size']) && is_int($args['size'])) {
            $this->size = $args['size'];
        }
        if (isset($args['imgWidth']) && is_int($args['imgWidth'])) {
            $this->imgWidth = $args['imgWidth'];
        }
        if (isset($args['imgHeight']) && is_int($args['imgHeight'])) {
            $this->imgHeight = $args['imgHeight'];
        }
        if (isset($args['folder']) && is_string($args['folder'])) {
            $this->folder = $args['folder'];
        }
    }

    protected function code(array $attrs = []): string
    {
        $attrs['yee-module'] = $this->getYeeModule('upload txcos');
        $attrs['class'] = 'form-inp up-image';
        $attrs['type'] = 'text';
        $attrs['data-field-name'] = 'file';
        $attrs['data-url'] = Config::get('txcos.upload_url');
        $attrs['data-web-url'] = Config::get('txcos.web_url');
        if (!empty($this->mode)) {
            $attrs['data-mode'] = $this->mode;
            if ($this->mode == 'imgGroup' && $this->size > 0) {
                $attrs['data-size'] = $this->size;
            }
        }
        if (!empty($this->extensions)) {
            $attrs['data-extensions'] = $this->extensions;
        }
        if (!empty($this->imgWidth)) {
            $attrs['data-img-width'] = $this->imgWidth;
        }
        if (!empty($this->imgHeight)) {
            $attrs['data-img-height'] = $this->imgHeight;
        }
        if ($attrs['data-mode'] == 'image') {
            if (empty($attrs['data-img-width'])) {
                $attrs['data-img-width'] = 300;
            }
            if (empty($attrs['data-img-height'])) {
                $attrs['data-img-height'] = 200;
            }
        } else {
            if (empty($attrs['data-img-width'])) {
                $attrs['data-img-width'] = 100;
            }
            if (empty($attrs['data-img-height'])) {
                $attrs['data-img-height'] = 100;
            }
        }
        if (!empty($this->folder)) {
            $attrs['data-folder'] = $this->folder;
        }
        return static::makeTag('input', ['attrs' => $attrs]);
    }
}