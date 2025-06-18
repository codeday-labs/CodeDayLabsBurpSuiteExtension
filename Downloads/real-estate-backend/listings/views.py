from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import SupabaseListing
from .serializers import SupabaseListingSerializer
from .scoring import get_population_growth_score, get_property_tax_score, has_adu_potential

class SupabaseListingListView(ListAPIView):
    queryset = SupabaseListing.objects.all().order_by('-id')
    serializer_class = SupabaseListingSerializer


class RankedListingView(APIView):
    def get(self, request):
        listings = SupabaseListing.objects.filter(state='WA')[:100]  # Limit for performance
        results = []
        for listing in listings:
            pop_score = get_population_growth_score(listing.city)
            state_tax_score = 1.0  # WA has no income tax
            tax_score = get_property_tax_score(listing.taxes_annual)
            adu_score = has_adu_potential(listing)

            # Weighting system
            total_score = (
                0.4 * pop_score +
                0.2 * state_tax_score +
                0.3 * tax_score +
                0.1 * adu_score
            )

            results.append({
                'id': listing.id,
                'city': listing.city,
                'taxes_annual': listing.taxes_annual,
                'adu': bool(adu_score),
                'score': round(total_score, 3),
                'price': listing.current_price,
                'remarks': listing.marketing_remarks
            })

        sorted_results = sorted(results, key=lambda x: x['score'], reverse=True)
        return Response(sorted_results)
