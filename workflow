{
  "query": {
    "bool": {
      "should": [
        {
          "match": {
            "message": "{{$misp_1.body.0.value}}"
          }
        },
        {
          "match": {
            "message": "{{$misp_1.body.1.value}}"
          }
        },
        {
          "match": {
            "message": "{{$misp_1.body.2.value}}"
          }
        }
      ]
    }
  }
}


