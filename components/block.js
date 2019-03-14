'use strict'
polarity.export = PolarityComponent.extend({

  dataPerPage: 5,


  allDataShowing: Ember.computed('block.data.details.body.results.length', 'maxData', function() {
    return this.get('maxData') >= this.get('block.data.details.body.results.length');
  }),

  maxData: null,
    init() {
      this.set('maxData', this.get('dataPerPage'));
      this._super(...arguments);
    },


  showEmail: Ember.computed('block.data.detauls.body.results.length', function() {
    const detailsLength = this.get('block.data.detauls.body.results.length');
    const viewState = Ember.A();
    for (let i = 0; i < detailsLength; i++) {
      viewState.push(false);
    }
    return viewState;
  }),
    actions: {
      showMoreData() {
        this.incrementProperty('maxData', this.get('dataPerPage'));
      },
      toggleScanner() {
            this.toggleProperty('isShowingDiv');
        },
      toggleVisibility() {
      this.toggleProperty('showEmail');
    }
    }
});
