"use strict";

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias("block.data.details.body"),

  severityTags: Ember.computed("details", function() {
    let severityLevel = Ember.A();
    let severityData = Ember.A();
    this.get("details.results").forEach(function(item) {
      if(item.severity !== undefined && item.severity !== null){
        severityData.push(item.severity);
    }
  });
    let severity = Math.max(...severityData);
    if(severity === 1){
      severityLevel.push("Highest Severity: MINIMAL");
    }else if(severity === 2){
      severityLevel.push("Highest Severity: LOW")
    }else if (severity === 3){
      severityLevel.push("Highest Severity: MEDIUM")
    }else if (severity === 4){
      severityLevel.push(" Highest Severity: HIGH")
    }else {
      severityLevel.push("Highest Severity: CRITICAL")
    }
    let severityTags = [... new Set(severityLevel)];
    return severityTags;
  }),

  confidenceTags: Ember.computed("details", function() {
    let confidenceData = Ember.A();
    this.get("details.results").forEach(function(item) {
      if(item.confidence !== undefined && item.confidence !== null){
        confidenceData.push("Confidence Score: " + item.confidence);
    }
  });

    return confidenceData;
  }),

  emailTags: Ember.computed("details", function() {
    let emailTags = [];
    this.get("details.results").forEach(function(item) {
      if(item.sender !== undefined && item.sender !== null){
        emailTags.push(item.sender);
      }
    });
    return [ ...new Set(emailTags)];
  }),

  metaTags: Ember.computed("details", function() {
    let metaTags = [];
    this.get("details.results").forEach(function(item) {
      if(Array.isArray(item.meta_data)){
        for(let i =0; i < item.meta_data.length; i++){
          metaTags.push(item.meta_data[i]);
        }
      }
    });
    return [...new Set(metaTags)];
  }),
  threatTags: Ember.computed("details", function() {
    let threats = [];
    this.get("details.results").forEach(function(item) {
      if(Array.isArray(item.threat_types)){
          for(let i =0; i < item.threat_types.length; i++){
            threats.push(item.threat_types[i]);
          }
      }
      });
    return [... new Set(threats)];
  })
});
