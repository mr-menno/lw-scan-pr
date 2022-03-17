let imageTag = {};

imageTag.processNameAndTag = function({IMAGE_NAME,IMAGE_TAG}) {
  IMAGE_TAG=(IMAGE_TAG||"").split("\n")[0];
  IMAGE_NAME=JSON.parse(IMAGE_NAME||"");
  IMAGE_TAG=JSON.parse(IMAGE_TAG||"");
  if(IMAGE_NAME && IMAGE_TAG) {
    let _tagged_name = IMAGE_NAME.match(/(.*):([^\/]+)$/);
    let _tagged_tag = IMAGE_TAG.match(/(.*):([^\/]+)$/);
    if(_tagged_name) {
      console.log("imageTag: found tagged IMAGE_NAME")
      return {IMAGE_NAME: _tagged_name[1], IMAGE_TAG: _tagged_name[2]};
    } else if(_tagged_tag) {
      console.log("imageTag: found image name in IMAGE_TAG")
      return {IMAGE_NAME: _tagged_tag[1], IMAGE_TAG: _tagged_tag[2]};
    }
    console.log("imageTag: successfully using IMAGE_NAME and IMAGE_TAG")
    return {
      IMAGE_NAME: IMAGE_NAME,
      IMAGE_TAG: IMAGE_TAG
    }
  } else if(IMAGE_TAG) {
    let _tagged = IMAGE_TAG.match(/(.*):([^\/]+)$/);
    if(_tagged) {
      console.log("imageTag: found image name in IMAGE_TAG (IMAGE_NAME unset)")
      return {IMAGE_NAME: _tagged[1], IMAGE_TAG: _tagged[2]};
    } else {
      console.error("imageTag: invalid IMAGE_NAME or IMAGE_TAG input");
      process.exit(2);
    }
  } else {
    console.error("imageTag: missing IMAGE_NAME and IMAGE_TAG");
    process.exit(1);
  }
}

module.exports = imageTag;