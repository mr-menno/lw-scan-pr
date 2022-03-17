const imageTag = require('./image_tag');

let result;

let tests = [
  {
    IMAGE_NAME: "test/test/image",
    IMAGE_TAG: "latest"
  },
  {
    IMAGE_NAME: "test/test/image",
    IMAGE_TAG: ""
  },
  {
    IMAGE_NAME: "test/test/image",
    IMAGE_TAG: "test/test/image:latest"
  },
  {
    IMAGE_NAME: "test/test/image:latest",
    IMAGE_TAG: "latest"
  },
  {
    IMAGE_NAME: "test/test/image:latest",
    IMAGE_TAG: "test/test/image:latest"
  },
  {
    IMAGE_NAME: "",
    IMAGE_TAG: "test/test/image:latest"
  },
  {
    IMAGE_NAME: "",
    IMAGE_TAG: "latest"
  },
  {}
]

tests.forEach(test => {
  console.log(imageTag.processNameAndTag(test));
})