
// Description: Java 25 in-memory RAM DbIO implementation for ServiceType.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamServiceTypeTable in-memory RAM DbIO implementation
 *	for ServiceType.
 */
public class CFSecRamServiceTypeTable
	implements ICFSecServiceTypeTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffServiceType > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffServiceType >();
	private Map< CFSecBuffServiceTypeByUDescrIdxKey,
			CFSecBuffServiceType > dictByUDescrIdx
		= new HashMap< CFSecBuffServiceTypeByUDescrIdxKey,
			CFSecBuffServiceType >();

	public CFSecRamServiceTypeTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffServiceType ensureRec(ICFSecServiceType rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecServiceType.CLASS_CODE) {
				return( ((CFSecBuffServiceTypeDefaultFactory)(schema.getFactoryServiceType())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecServiceType createServiceType( ICFSecAuthorization Authorization,
		ICFSecServiceType iBuff )
	{
		final String S_ProcName = "createServiceType";
		
		CFSecBuffServiceType Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextServiceTypeIdGen();
		Buff.setRequiredServiceTypeId( pkey );
		CFSecBuffServiceTypeByUDescrIdxKey keyUDescrIdx = (CFSecBuffServiceTypeByUDescrIdxKey)schema.getFactoryServiceType().newByUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ServiceTypeUDescrIdx",
				"ServiceTypeUDescrIdx",
				keyUDescrIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecServiceType.CLASS_CODE) {
				CFSecBuffServiceType retbuff = ((CFSecBuffServiceType)(schema.getFactoryServiceType().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecServiceType readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerived";
		ICFSecServiceType buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecServiceType lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerived";
		ICFSecServiceType buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecServiceType[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamServiceType.readAllDerived";
		ICFSecServiceType[] retList = new ICFSecServiceType[ dictByPKey.values().size() ];
		Iterator< CFSecBuffServiceType > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecServiceType readDerivedByUDescrIdx( ICFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerivedByUDescrIdx";
		CFSecBuffServiceTypeByUDescrIdxKey key = (CFSecBuffServiceTypeByUDescrIdxKey)schema.getFactoryServiceType().newByUDescrIdxKey();
		key.setRequiredDescription( Description );

		ICFSecServiceType buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecServiceType readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerivedByIdIdx() ";
		ICFSecServiceType buff;
		if( dictByPKey.containsKey( ServiceTypeId ) ) {
			buff = dictByPKey.get( ServiceTypeId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecServiceType readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamServiceType.readBuff";
		ICFSecServiceType buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecServiceType.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecServiceType lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecServiceType buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecServiceType.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecServiceType[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamServiceType.readAllBuff";
		ICFSecServiceType buff;
		ArrayList<ICFSecServiceType> filteredList = new ArrayList<ICFSecServiceType>();
		ICFSecServiceType[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecServiceType.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecServiceType[0] ) );
	}

	public ICFSecServiceType readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamServiceType.readBuffByIdIdx() ";
		ICFSecServiceType buff = readDerivedByIdIdx( Authorization,
			ServiceTypeId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecServiceType.CLASS_CODE ) ) {
			return( (ICFSecServiceType)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecServiceType readBuffByUDescrIdx( ICFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamServiceType.readBuffByUDescrIdx() ";
		ICFSecServiceType buff = readDerivedByUDescrIdx( Authorization,
			Description );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecServiceType.CLASS_CODE ) ) {
			return( (ICFSecServiceType)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecServiceType updateServiceType( ICFSecAuthorization Authorization,
		ICFSecServiceType iBuff )
	{
		CFSecBuffServiceType Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffServiceType existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateServiceType",
				"Existing record not found",
				"Existing record not found",
				"ServiceType",
				"ServiceType",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateServiceType",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffServiceTypeByUDescrIdxKey existingKeyUDescrIdx = (CFSecBuffServiceTypeByUDescrIdxKey)schema.getFactoryServiceType().newByUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecBuffServiceTypeByUDescrIdxKey newKeyUDescrIdx = (CFSecBuffServiceTypeByUDescrIdxKey)schema.getFactoryServiceType().newByUDescrIdxKey();
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Check unique indexes

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateServiceType",
					"ServiceTypeUDescrIdx",
					"ServiceTypeUDescrIdx",
					newKeyUDescrIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffServiceType > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

		return(Buff);
	}

	public void deleteServiceType( ICFSecAuthorization Authorization,
		ICFSecServiceType iBuff )
	{
		final String S_ProcName = "CFSecRamServiceTypeTable.deleteServiceType() ";
		CFSecBuffServiceType Buff = ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffServiceType existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteServiceType",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckServiceTypeDeployed[] = schema.getTableService().readDerivedByTypeIdx( Authorization,
						existing.getRequiredServiceTypeId() );
		if( arrCheckServiceTypeDeployed.length > 0 ) {
			schema.getTableService().deleteServiceByTypeIdx( Authorization,
						existing.getRequiredServiceTypeId() );
		}
		CFSecBuffServiceTypeByUDescrIdxKey keyUDescrIdx = (CFSecBuffServiceTypeByUDescrIdxKey)schema.getFactoryServiceType().newByUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffServiceType > subdict;

		dictByPKey.remove( pkey );

		dictByUDescrIdx.remove( keyUDescrIdx );

	}
	public void deleteServiceTypeByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffServiceType cur;
		LinkedList<CFSecBuffServiceType> matchSet = new LinkedList<CFSecBuffServiceType>();
		Iterator<CFSecBuffServiceType> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffServiceType> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffServiceType)(schema.getTableServiceType().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceTypeId() ));
			deleteServiceType( Authorization, cur );
		}
	}

	public void deleteServiceTypeByUDescrIdx( ICFSecAuthorization Authorization,
		String argDescription )
	{
		CFSecBuffServiceTypeByUDescrIdxKey key = (CFSecBuffServiceTypeByUDescrIdxKey)schema.getFactoryServiceType().newByUDescrIdxKey();
		key.setRequiredDescription( argDescription );
		deleteServiceTypeByUDescrIdx( Authorization, key );
	}

	public void deleteServiceTypeByUDescrIdx( ICFSecAuthorization Authorization,
		ICFSecServiceTypeByUDescrIdxKey argKey )
	{
		CFSecBuffServiceType cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffServiceType> matchSet = new LinkedList<CFSecBuffServiceType>();
		Iterator<CFSecBuffServiceType> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffServiceType> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffServiceType)(schema.getTableServiceType().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceTypeId() ));
			deleteServiceType( Authorization, cur );
		}
	}
}
